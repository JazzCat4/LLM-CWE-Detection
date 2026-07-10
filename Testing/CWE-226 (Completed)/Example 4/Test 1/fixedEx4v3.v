module secret_fifo_secure (
    input  wire        clk,
    input  wire        rst,

    // Original interface
    input  wire        push,
    input  wire        pop,
    input  wire [63:0] secret_in,
    output reg  [63:0] secret_out,
    output reg         empty,
    output reg         full,

    // Security / privilege interface
    input  wire        secure_write_en,  // privilege to write secrets
    input  wire        secure_read_en,   // privilege to read secrets
    input  wire        domain_switch     // context switch between trust domains
);

    reg [63:0] secret [0:3];
    reg [1:0] head, tail;
    reg [2:0] count;

    // Scrub procedure: zero all secrets and reset pointers/state
    task scrub_all;
        integer j;
        begin
            for (j = 0; j < 4; j = j + 1) begin
                secret[j] <= 64'h0;
            end
            head       <= 0;
            tail       <= 0;
            count      <= 0;
            secret_out <= 64'h0;
        end
    endtask

    always @(posedge clk) begin
        if (rst || domain_switch) begin
            // CWE-226, CWE-1189: scrub secrets on reset / domain switch
            scrub_all();
        end else begin
            // Secure write path: only privileged writes allowed
            if (push && secure_write_en && !full) begin
                secret[tail] <= secret_in;
                tail         <= tail + 1;
                count        <= count + 1;
            end

            // Secure read path: only privileged reads allowed
            if (pop && secure_read_en && !empty) begin
                // Trusted read: return secret and zeroize entry (CWE-226)
                secret_out   <= secret[head];
                secret[head] <= 64'h0;
                head         <= head + 1;
                count        <= count - 1;
            end else if (pop && !secure_read_en) begin
                // Untrusted read attempt: return 0, do not change pointers/count (CWE-1262)
                secret_out <= 64'h0;
            end
        end
    end

    always @(*) begin
        empty = (count == 0);
        full  = (count == 3);
    end

endmodule
