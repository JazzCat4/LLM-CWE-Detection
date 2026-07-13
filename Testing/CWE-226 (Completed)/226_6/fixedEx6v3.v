module secret_fifo_secure (
    input  wire        clk,
    input  wire        rst,

    // Original interface
    input  wire        push,
    input  wire        pop,
    input  wire [63:0] key_in,
    output reg  [63:0] key_out,
    output reg         empty,
    output reg         full,

    // Security
    input  wire        priv_access,
    input  wire        lock_set,
    input  wire        debug_mode,
    input  wire        glitch_detect,

    output reg         locked,
    output reg         error_flag
);

    reg [63:0] key [0:3];
    reg [1:0]  head, tail;
    reg [2:0]  count, count_shadow;

    integer i;

    always @(posedge clk) begin
        // Glitch → safe state
        if (glitch_detect) begin
            error_flag <= 1'b1;
            head <= 0; tail <= 0; count <= 0; count_shadow <= 0;
            key_out <= 64'h0;
            for (i=0;i<4;i=i+1) key[i] <= 64'h0;
        end

        else if (rst) begin
            // Reset clears lock (fix)
            locked <= 1'b0;
            error_flag <= 1'b0;
            head <= 0; tail <= 0; count <= 0; count_shadow <= 0;
            key_out <= 64'h0;
            for (i=0;i<4;i=i+1) key[i] <= 64'h0;
        end

        else begin
            // Lock is set-only during normal operation
            if (lock_set)
                locked <= 1'b1;

            // Glitch detection via redundant count
            if (count != count_shadow) begin
                error_flag <= 1'b1;
                head <= 0; tail <= 0; count <= 0; count_shadow <= 0;
                key_out <= 64'h0;
                for (i=0;i<4;i=i+1) key[i] <= 64'h0;
            end

            else if (!error_flag && !debug_mode) begin
                // Privileged push
                if (push && priv_access && !locked && !full) begin
                    key[tail] <= key_in;
                    tail <= tail + 1'b1;
                    count <= count + 1'b1;
                    count_shadow <= count_shadow + 1'b1;
                end

                // Privileged pop
                if (pop && priv_access && !locked && !empty) begin
                    key_out <= key[head];
                    key[head] <= 64'h0; // zeroize after use
                    head <= head + 1'b1;
                    count <= count - 1'b1;
                    count_shadow <= count_shadow - 1'b1;
                end
            end
        end
    end

    always @(*) begin
        empty = (count == 0);
        full  = (count == 4);
    end

endmodule
