module SecureEx1(
    input  wire        clk,
    input  wire        reset,

    // Original auth interface
    input  wire        start_auth,
    input  wire [31:0] challenge,
    input  wire [31:0] response,

    // New security controls
    input  wire        auth_priv,      // privilege signal (must be 1 to allow auth)
    input  wire        glitch_detect,  // from glitch detector
    input  wire [31:0] mask,           // masking value for side-channel hardening

    output reg         unlocked
);

    // Secret key (still constant, but used via a scrubbed register)
    localparam [31:0] SECRET_KEY = 32'hC0FFEE42;

    // FSM states (defensive encoding, ERROR is safe sink)
    localparam [1:0] IDLE     = 2'b00;
    localparam [1:0] CHECKING = 2'b01;
    localparam [1:0] UNLOCKED = 2'b10;
    localparam [1:0] ERROR    = 2'b11;

    reg [1:0] state, next_state;
    reg [31:0] key_reg;

    wire [31:0] masked_challenge;
    wire [31:0] masked_response;

    // Masked datapath to reduce direct key-dependent switching
    assign masked_challenge = (challenge ^ key_reg) ^ mask;
    assign masked_response  = response ^ mask;

    // Combinational next-state logic
    always @(*) begin
        // Defensive default: on glitch, go to ERROR
        if (glitch_detect) begin
            next_state = ERROR;
        end else begin
            next_state = state;
            case (state)
                IDLE: begin
                    // Only privileged context can start auth
                    if (auth_priv && start_auth)
                        next_state = CHECKING;
                end

                CHECKING: begin
                    // Constant-time style compare (single combinational equality)
                    if (masked_response == masked_challenge)
                        next_state = UNLOCKED;
                    else
                        next_state = IDLE;
                end

                UNLOCKED: begin
                    // Stay unlocked until reset or glitch
                    next_state = UNLOCKED;
                end

                ERROR: begin
                    // Safe sink; remain here until reset
                    next_state = ERROR;
                end

                default: begin
                    // Any illegal encoding defaults to ERROR
                    next_state = ERROR;
                end
            endcase
        end
    end

    // Sequential state update and scrubbing
    always @(posedge clk or posedge reset) begin
        if (reset) begin
            state    <= IDLE;
            unlocked <= 1'b0;
            key_reg  <= 32'b0;  // scrub key on reset
        end else begin
            // Glitch forces safe state and scrubbing
            if (glitch_detect) begin
                state    <= ERROR;
                unlocked <= 1'b0;
                key_reg  <= 32'b0;
            end else begin
                state <= next_state;

                // Load key only when entering CHECKING from IDLE
                if (state == IDLE && next_state == CHECKING && auth_priv && start_auth)
                    key_reg <= SECRET_KEY;
                // Scrub key when leaving CHECKING
                else if (state == CHECKING && next_state != CHECKING)
                    key_reg <= 32'b0;

                // Unlock only when FSM is in UNLOCKED
                if (next_state == UNLOCKED)
                    unlocked <= 1'b1;
                else if (next_state != UNLOCKED)
                    unlocked <= 1'b0;
            end
        end
    end

endmodule
