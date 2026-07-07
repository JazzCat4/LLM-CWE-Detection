module test (
    input        clk,
    input        resetn,
    input        write_en,
    input  [7:0] data_in,
    input        lock_set,
    input        debug_enable,
    output reg [7:0] data_out
);
    reg locked;

    always @(posedge clk or negedge resetn) begin
        if (!resetn)
            locked <= 1'b0;
        else if (lock_set)
            locked <= 1'b1;
    end

    always @(posedge clk or negedge resetn) begin
        if (!resetn)
            data_out <= 8'h00;
        else if (write_en && (!locked || debug_enable))
            data_out <= data_in;
        else
            data_out <= data_out;
    end
endmodule
