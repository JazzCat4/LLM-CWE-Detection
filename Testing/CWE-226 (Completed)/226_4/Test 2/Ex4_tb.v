`timescale 1ns/1ps

module tb_secret_fifo;

    reg clk, rst;
    reg push, pop;
    reg [63:0] secret_in;
    wire [63:0] secret_out;
    wire empty, full;

    // DUT
    secret_fifo dut (
        .clk(clk),
        .rst(rst),
        .push(push),
        .pop(pop),
        .secret_in(secret_in),
        .secret_out(secret_out),
        .empty(empty),
        .full(full)
    );

    // Clock
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

        $display("\n=== CWE-226 TEST: Secrets persist across reset ===");
        push_word(64'hDEADBEEFCAFEBABE);   // Write secret
        pop_word;                          // Read it once
        $display("Before reset, secret_out = %h", secret_out);

        rst = 1; @(posedge clk); rst = 0;  // Reset but secret[] is NOT cleared

        pop_word;                          // Pop again after reset
        $display("After reset, secret_out = %h (should NOT persist!)", secret_out);

        $display("\n=== CWE-1189 TEST: Untrusted agent can read/write secrets ===");
        push_word(64'h1111222233334444);   // Untrusted write
        pop_word;                          // Untrusted read
        $display("Untrusted read = %h (should be blocked!)", secret_out);

        $display("\n=== CWE-1256 TEST: Unprivileged control of hardware features ===");
        rst = 1; @(posedge clk); rst = 0;  // Unprivileged reset
        push_word(64'hAAAAAAAAAAAAAAAA);   // Unprivileged write
        pop_word;                          // Unprivileged read
        $display("Unprivileged access = %h (should require privilege!)", secret_out);

        $display("\n=== CWE-1260 TEST: Illegal count states & permissive behavior ===");
        // Force illegal state by glitching count via simultaneous push/pop
        push = 1; pop = 1; secret_in = 64'hBBBBBBBBBBBBBBBB;
        @(posedge clk);
        push = 0; pop = 0;

        $display("Count = %0d (should never exceed 3!)", dut.count);
        if (dut.count > 3)
            $display("ILLEGAL STATE DETECTED: count > 3, module fails open!");

        $display("\n=== CWE-1262 TEST: No access control on secret_out ===");
        push_word(64'h9999AAAABBBBCCCC);
        pop_word;
        $display("secret_out = %h (should be masked or privilege-gated!)", secret_out);

        $display("\n=== CWE-1247 TEST: Clock glitch vulnerability ===");
        // Simulate a glitch by shortening a clock period
        #2 clk = ~clk;  // glitch
        #2 clk = ~clk;

        push_word(64'h123456789ABCDEF0);
        pop_word;
        $display("After glitch, secret_out = %h (glitch may corrupt pointers!)", secret_out);

        $display("\n=== CWE-1234 TEST: Debug/override paths (module has none, but test confirms no lock bits) ===");
        $display("No lock bits or debug gating present — any agent can override behavior.");

        $display("\n=== TEST COMPLETE ===");
        $finish;
    end

endmodule
