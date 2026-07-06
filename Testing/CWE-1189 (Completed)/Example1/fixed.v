module Ex1_secure (
    input  wire        clk,
    input  wire        reset,
    input  wire        glitch_detect,   // CWE-1247: glitch detector

    // Secure CPU master (trusted)
    input  wire        cpu_req,
    input  wire [7:0]  cpu_addr,
    input  wire [31:0] cpu_wdata,
    input  wire        cpu_we,
    output reg  [31:0] cpu_rdata,

    // Peripheral master (untrusted)
    input  wire        periph_req,
    input  wire [7:0]  periph_addr,
    input  wire [31:0] periph_wdata,
    input  wire        periph_we,
    output reg  [31:0] periph_rdata
);

    // -----------------------------
    // Memory partitioning & access control
    // -----------------------------
    // CWE-1189 / CWE-1262:
    // - Separate secure and peripheral memories
    // - Explicit address-based permissions
    reg [31:0] mem_secure  [0:255];  // CPU-only, sensitive
    reg [31:0] mem_periph  [0:255];  // Peripheral-only

    // Peripheral allowed address range (example: 0x80-0xFF)
    wire periph_addr_allowed = (periph_addr >= 8'h80);

    // -----------------------------
    // Glitch-resistant arbitration FSM
    // -----------------------------
    // CWE-1247: multi-bit encoding + error state
    localparam ST_ERROR   = 2'b00;
    localparam ST_CPU     = 2'b01;
    localparam ST_PERIPH  = 2'b10;

    reg [1:0] turn_state;

    // Scrubbing control
    reg scrub_done;

    integer i;

    // -----------------------------
    // Reset & scrubbing (CWE-226)
    // -----------------------------
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            // Defensive default: error state until scrubbing completes
            turn_state <= ST_ERROR;
            scrub_done <= 1'b0;

            // Zero-fill all memories (scrub sensitive data)
            for (i = 0; i < 256; i = i + 1) begin
                mem_secure[i] <= 32'b0;
                mem_periph[i] <= 32'b0;
            end

        end else if (glitch_detect) begin
            // Glitch forces safe error state
            turn_state <= ST_ERROR;
            scrub_done <= 1'b0;

        end else begin
            // After first post-reset cycle, scrubbing is considered done
            scrub_done <= 1'b1;

            // Normal arbitration only when scrubbed and no glitch
            case (turn_state)
                ST_ERROR: begin
                    // Move to CPU as safe default once scrubbed
                    if (scrub_done)
                        turn_state <= ST_CPU;
                end
                ST_CPU:     turn_state <= ST_PERIPH;
                ST_PERIPH:  turn_state <= ST_CPU;
                default:    turn_state <= ST_ERROR; // defensive default
            endcase
        end
    end

    // -----------------------------
    // Access logic with isolation & access control
    // -----------------------------
    always @(posedge clk) begin
        // Default outputs
        cpu_rdata    <= 32'b0;
        periph_rdata <= 32'b0;

        // Only allow accesses when not in error state
        if (turn_state == ST_CPU && cpu_req && scrub_done) begin
            // CPU: full access to secure memory only
            if (cpu_we)
                mem_secure[cpu_addr] <= cpu_wdata;
            cpu_rdata <= mem_secure[cpu_addr];

        end else if (turn_state == ST_PERIPH && periph_req && scrub_done) begin
            // Peripheral: restricted access to its own memory region only
            if (periph_addr_allowed) begin
                if (periph_we)
                    mem_periph[periph_addr] <= periph_wdata;
                periph_rdata <= mem_periph[periph_addr];
            end else begin
                // Default-deny for disallowed addresses (CWE-1262)
                periph_rdata <= 32'b0;
            end
        end
    end

endmodule
