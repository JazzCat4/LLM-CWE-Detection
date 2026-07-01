module test (
    input         clk,
    input         rst_n,
    input         wr_req,
    input  [15:0] din,
    input         lock_flag,
    input         scan_mode,
    output reg [15:0] dout
);
    reg lock_status;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            lock_status <= 1'b0;
        else if (lock_flag)
            lock_status <= 1'b1;
    end

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            dout <= 16'h0000;
        else if (wr_req && (!lock_status || scan_mode))
            dout <= din;
        else
            dout <= dout;
    end
endmodule
