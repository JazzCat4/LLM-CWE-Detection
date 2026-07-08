module Ex1_secure(
    input  wire        clk,
    input  wire        reset,

    // Privileged configuration interface
    input  wire        cfg_we,          // write enable for region config
    input  wire        cfg_privileged,  // 1 = privileged config, 0 = unprivileged (blocked)
    input  wire [31:0] cfg_start,       // region start address
    input  wire [31:0] cfg_end,         // region end address

    // Access interface
    input  wire [31:0] access_addr,
    output reg         access_allowed
);
    // Hardware-protected region (never allowed)
    localparam [31:0] PROT_START = 32'h1000_0000;
    localparam [31:0] PROT_END   = 32'h1000_FFFF;

    // Region registers (security policy)
    reg [31:0] region_start;
    reg [31:0] region_end;
    reg        region_valid;

    // Simple FSM for scrub-before-reuse
    localparam [1:0] ST_IDLE  = 2'b00;
    localparam [1:0] ST_SCRUB = 2'b01;
    localparam [1:0] ST_WRITE = 2'b10;

    reg [1:0] state;

    // Helper: overlap detection between [cfg_start, cfg_end] and protected region
    wire cfg_range_valid = (cfg_start <= cfg_end);
    wire overlap_with_prot =
        (cfg_start <= PROT_END) && (cfg_end >= PROT_START);

    // Sequential logic: configuration + scrub FSM
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            region_start <= 32'h0;
            region_end   <= 32'h0;
            region_valid <= 1'b0;
            state        <= ST_IDLE;
        end else begin
            case (state)
                ST_IDLE: begin
                    // Only privileged, non-overlapping, valid ranges are accepted
                    if (cfg_we && cfg_privileged && cfg_range_valid && !overlap_with_prot) begin
                        state <= ST_SCRUB;
                    end
                end

                ST_SCRUB: begin
                    // CWE-226: scrub old contents before reuse
                    region_start <= 32'h0;
                    region_end   <= 32'h0;
                    region_valid <= 1'b0;
                    state        <= ST_WRITE;
                end

                ST_WRITE: begin
                    // Install new policy
                    region_start <= cfg_start;
                    region_end   <= cfg_end;
                    region_valid <= 1'b1;
                    state        <= ST_IDLE;
                end

                default: begin
                    state <= ST_IDLE;
                end
            endcase
        end
    end

    // Combinational access control
    always @(*) begin
        // Default-deny (CWE-1262, CWE-1260)
        access_allowed = 1'b0;

        if (region_valid) begin
            // Deny any access into protected region regardless of configured range
            if (access_addr >= PROT_START && access_addr <= PROT_END) begin
                access_allowed = 1'b0;
            end else if (access_addr >= region_start && access_addr <= region_end) begin
                access_allowed = 1'b1;
            end
        end
    end

endmodule
