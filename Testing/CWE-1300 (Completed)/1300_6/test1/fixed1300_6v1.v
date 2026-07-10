module test_secure (
    input  wire        clk,
    input  wire        rst_n,
    input  wire        secret_bit,
    input  wire        clear_acc,   // explicit scrub / context-switch signal
    input  wire [15:0] data_in,
    output reg  [15:0] acc
);

    // Compute both branches in parallel (constant-time style)
    wire [15:0] add_res = acc + data_in;
    wire [15:0] sub_res = acc - data_in;

    // Secret only controls a mux, not whether logic is active
    wire [15:0] acc_next = secret_bit ? add_res : sub_res;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            // CWE-226: scrub on reset
            acc <= 16'd0;
        end else if (clear_acc) begin
            // CWE-226: scrub on context switch / release
            acc <= 16'd0;
        end else begin
            // CWE-1300: both datapaths active, secret only selects output
            acc <= acc_next;
        end
    end

endmodule
