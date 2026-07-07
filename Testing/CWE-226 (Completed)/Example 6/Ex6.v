module secret_fifo (
    input wire clk,
    input wire rst,
    input wire push,
    input wire pop,
    input wire [63:0] key_in,
    output reg [63:0] key_out,
    output reg empty,
    output reg full
);

    reg [63:0] key [0:3];
    reg [1:0] head, tail;
    reg [2:0] count;

    always @(posedge clk) begin
        if (rst) begin
            head <= 0;
            tail <= 0;
            count <= 0;
            key_out <= 0;
        end else begin
            if (push && !full) begin
                key[tail] <= key_in;
                tail <= tail + 1;
                count <= count + 1;
            end
            if (pop && !empty) begin
                key_out <= key[head];
                head <= head + 1;
                count <= count - 1;
            end
        end
    end

    always @(*) begin
        empty = (count == 0);
        full  = (count == 3);
    end
    
endmodule
