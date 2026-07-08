module test3(
    input        clk,
    input        rst_n,
    input        start,
    output reg   done
);

    reg [1:0] stage;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            stage <= 2'b00;
        else begin
            case (stage)
                2'b00: if (start) stage <= 2'b01;
                2'b01: stage <= 2'b10;
                2'b10: stage <= 2'b11;
                2'b11: stage <= 2'b00;
            endcase
        end
    end

    always @(posedge clk) begin
        done <= (stage == 2'b11);
    end

endmodule