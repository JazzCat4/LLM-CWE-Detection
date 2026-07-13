`timescale 1ns/1ps

module tb_secret_fifo_secure;

    reg clk, rst;
    reg push, pop;
    reg [63:0] secret_in;
    wire [63:0] secret_out;
    wire empty, full;

    reg priv_ok;
    reg domain_switch;
    reg lock_set;
    reg glitch_detect;
    reg debug_mode;

    secret_fifo_secure dut (
        .clk(clk),
        .rst(rst),
        .push(push),
        .pop(pop),
        .secret_in(secret_in),
        .secret_out(secret_out),
        .empty(empty),
        .full(full),
        .priv_ok(priv_ok),
        .domain_switch(domain_switch),
        .lock_set(lock_set),
        .glitch_detect(glitch_detect),
        .debug_mode(debug_mode)
    );

    always #5 clk = ~clk;

    task push_word(input [63:0] w);
        begin
            push = 1; secret_in = w;
            @(posedge clk);
            push = 0;
        end
    endtask

    task pop_word;
        begin
            pop = 1;
            @(posedge clk);
            pop = 0;
        end
    endtask

    initial begin
        clk = 0;
        rst = 0;
        push = 0;
        pop = 0;
        secret_in = 0;
        priv_ok = 0;
        domain_switch = 0;
        lock_set = 0;
        glitch_detect = 0;
        debug_mode = 0;

        // Boot: configure and lock
        $display("\n=== Secure configuration and lock ===");
        priv_ok   = 1;
        lock_set  = 1;   // fuse set
        @(posedge clk);

        // CWE-226: secrets scrubbed on reset
        $display("\n=== CWE-226: Scrub on reset ===");
        push_word(64'hDEADBEEFCAFEBABE);
        pop_word;
        $display("Before reset, secret_out = %h", secret_out);

        rst = 1; @(posedge clk); rst = 0;
        pop_word;
        $display("After reset, secret_out = %h (should be 0)", secret_out);

        // CWE-1189: scrub on domain switch
        $display("\n=== CWE-1189: Scrub on domain switch ===");
        push_word(64'h1111222233334444);
        domain_switch = 1; @(posedge clk); domain_switch = 0;
        pop_word;
        $display("After domain switch, secret_out = %h (should be 0)", secret_out);

        // CWE-1256 / 1262: unprivileged access denied
        $display("\n=== CWE-1256 / 1262: Unprivileged access denied ===");
        priv_ok = 0;
        push_word(64'hAAAAAAAAAAAAAAAA);
        pop_word;
        $display("Unprivileged secret_out = %h (should be 0)", secret_out);
        priv_ok = 1;

        // CWE-1260: bounded count, no illegal states
        $display("\n=== CWE-1260: Bounded count ===");
        push_word(64'hBBBBBBBBBBBBBBBB);
        push_word(64'hCCCCCCCCCCCCCCCC);
        push_word(64'hDDDDDDDDDDDDDDDD);
        push_word(64'hEEEEEEEEEEEEEEEE); // should be blocked when full
        $display("Count (internal) = %0d (should be <= 3)", dut.count);

        // CWE-1247: glitch forces safe error state
        $display("\n=== CWE-1247: Glitch forces error state ===");
        glitch_detect = 1;
        @(posedge clk);
        push_word(64'h123456789ABCDEF0); // should be blocked
        pop_word;
        $display("After glitch, secret_out = %h (should be 0)", secret_out);
        glitch_detect = 0;

        // CWE-1234: debug cannot override lock
        $display("\n=== CWE-1234: Debug cannot bypass lock ===");
        debug_mode = 1;
        push_word(64'h9999AAAABBBBCCCC);
        pop_word;
        $display("In debug, secret_out = %h (should be 0)", secret_out);
        debug_mode = 0;

        $display("\n=== SECURE TEST COMPLETE ===");
        $finish;
    end

endmodule
