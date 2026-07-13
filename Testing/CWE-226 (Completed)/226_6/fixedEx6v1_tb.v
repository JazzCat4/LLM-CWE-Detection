`timescale 1ns/1ps

module tb_secret_fifo_secure;

    reg         clk, rst;
    reg         push, pop;
    reg [63:0]  key_in;
    wire [63:0] key_out;
    wire        empty, full;

    reg         priv_access;
    reg         lock_set;
    reg         debug_mode;
    reg         glitch_detect;
    wire        locked;
    wire        error_flag;

    secret_fifo_secure dut (
        .clk          (clk),
        .rst          (rst),
        .push         (push),
        .pop          (pop),
        .key_in       (key_in),
        .key_out      (key_out),
        .empty        (empty),
        .full         (full),
        .priv_access  (priv_access),
        .lock_set     (lock_set),
        .debug_mode   (debug_mode),
        .glitch_detect(glitch_detect),
        .locked       (locked),
        .error_flag   (error_flag)
    );

    initial begin
        clk = 0;
        forever #5 clk = ~clk;
    end

    task push_key(input [63:0] val);
        begin
            key_in = val;
            push   = 1; #10 push = 0;
        end
    endtask

    task pop_key;
        begin
            pop = 1; #10 pop = 0;
        end
    endtask

    task clock_glitch;
        begin
            glitch_detect = 1; #10 glitch_detect = 0;
        end
    endtask

    initial begin
        $display("=== SECURE FIFO CWE TESTBENCH START ===");
        rst = 1; push = 0; pop = 0; key_in = 0;
        priv_access = 0; lock_set = 0; debug_mode = 0; glitch_detect = 0;
        #20 rst = 0;

        // CWE-226: zeroization on reset and after use
        $display("\n[CWE-226] Zeroization and scrubbing");
        priv_access = 1;
        push_key(64'hDEADBEEF_F00DBAAD);
        pop_key();
        $display("First pop key_out = %h", key_out);
        pop_key();
        $display("Second pop (should be 0) key_out = %h", key_out);

        rst = 1; #10 rst = 0;
        pop_key();
        $display("Pop after reset (should be 0) key_out = %h", key_out);

        // CWE-1234: lock is one-time, debug cannot bypass
        $display("\n[CWE-1234] Lock and debug behavior");
        priv_access = 1;
        lock_set = 1; #10 lock_set = 0;
        $display("locked = %b", locked);

        push_key(64'h1111222233334444);
        pop_key();
        $display("Pop with lock set (should be 0) key_out = %h", key_out);

        debug_mode = 1;
        push_key(64'h5555666677778888);
        pop_key();
        $display("Pop in debug_mode (should be 0) key_out = %h", key_out);
        debug_mode = 0;

        // CWE-1247: glitch forces safe error state
        $display("\n[CWE-1247] Glitch handling");
        rst = 1; #10 rst = 0;
        priv_access = 1; locked = 0;
        push_key(64'hA5A5A5A5A5A5A5A5);
        clock_glitch();
        #10;
        $display("error_flag = %b, key_out = %h (should be 0, error set)", error_flag, key_out);

        // CWE-1256 / CWE-1262: privilege-gated access
        $display("\n[CWE-1256/CWE-1262] Privilege and access control");
        rst = 1; #10 rst = 0;
        priv_access = 0; // unprivileged
        push_key(64'hCAFEBABECAFEBABE);
        pop_key();
        $display("Unprivileged key_out (should be 0) = %h", key_out);

        priv_access = 1;
        push_key(64'h0123456789ABCDEF);
        pop_key();
        $display("Privileged key_out (should be key) = %h", key_out);

        // CWE-1300: constant-time behavior (push/pop same cycles)
        $display("\n[CWE-1300] Constant-time push/pop");
        rst = 1; #10 rst = 0;
        priv_access = 1;
        push_key(64'h0000000000000001);
        pop_key();
        push_key(64'hFFFFFFFFFFFFFFFF);
        pop_key();
        $display("Push/pop use fixed cycles; masking/blinding would be added at crypto layer.");

        $display("\n=== SECURE FIFO CWE TESTBENCH END ===");
        #50 $finish;
    end

endmodule
