//https://cwe.mitre.org/data/definitions/1247.html
// A single-cycle authentication check can be bypassed by glitching the clock or voltage
module cwe1247(
    input wire clk,
    input wire reset,

    input wire start_auth,
    input wire [31:0] challenge,
    input wire [31:0] response,

    output reg unlocked
);

// Secret key used for challenge-response
localparam [31:0] SECRET_KEY = 32'hC0FFEE42;

// FSM states
localparam [1:0] IDLE = 2'b00;
localparam [1:0] CHECKING = 2'b01;
localparam [1:0] UNLOCKED = 2'b10;

reg [1:0] state, next_state;

// Vulnerable combination next-state logic
always @(*) begin
    next_state = state;

    case (state)
    IDLE: begin
        if (start_auth) next_state = CHECKING;
    end

    CHECKING: begin
        // Auth. is decided in a single cycle, voltage/clock glitch can flip comparator output
        if (response == (challenge ^ SECRET_KEY)) next_state = UNLOCKED;
        else next_state = IDLE;
    end

    UNLOCKED: begin
        next_state = UNLOCKED;
    end
    endcase
end

// Sequential state update
always @(posedge clk or posedge reset) begin
    if (reset) begin
        state <= IDLE;
        unlocked <= 1'b0;
    end else begin
        state <= next_state;

        if (state == UNLOCKED) unlocked <= 1'b1;
    end
end

endmodule