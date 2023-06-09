// Copyright 2023 ETH Zurich and University of Bologna.
// Copyright and related rights are licensed under the Solderpad Hardware
// License, Version 0.51 (the "License"); you may not use this file except in
// compliance with the License.  You may obtain a copy of the License at
// http://solderpad.org/licenses/SHL-0.51. Unless required by applicable law
// or agreed to in writing, software, hardware and materials distributed under
// this License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// Author: Flavien Solt, ETH Zurich

/**
* This is a memory mapped interrupt generator that generates tainted interrupt signals
* It contains some memory mapped registers:
* - REG_IRQS:        a register for the interrupt types to fire.
* - REG_IRQ_TAINTS:  a register for the interrupt types to fire.
* - REG_CAUSE:       a register for the interrupt cause.
* - REG_CAUSE_TAINT: a register for the interrupt cause taint.
* - REG_DELAY:       a register for a delay between the write to the commit and the effect. Takes effect immediately (or after the current commit counting down) and does not require to be committed.
* - REG_COMMIT:      a register for the changes are committed upon a write to this register. The other registers are NOT cleared when committed.
*
* If two commits are issued within a delay period, the first commit may not be visible.
*/


module custom_irqgen #(
  parameter logic [31:0] ADDRMAP_REG_IRQS,
  parameter logic [31:0] ADDRMAP_REG_IRQ_TAINTS,
  parameter logic [31:0] ADDRMAP_REG_CAUSE,
  parameter logic [31:0] ADDRMAP_REG_CAUSE_TAINT,
  parameter logic [31:0] ADDRMAP_REG_DELAY,
  parameter logic [31:0] ADDRMAP_REG_COMMIT,

  parameter type data_t,
  parameter type strb_t,
  parameter type addr_t,

  localparam int unsigned ID_INT_NMI      = 0,
  localparam int unsigned ID_INT_EXTERNAL = 1,
  localparam int unsigned ID_INT_SOFTWARE = 2,
  localparam int unsigned ID_INT_TIMER    = 3,

  localparam type delay_t = logic [31:0]
) (
	input clk_i,
  input rst_ni,

  // Memory interface
  input  logic  data_mem_req_i,
  output logic  data_mem_gnt_o,
  input  addr_t data_mem_addr_i,
  input  data_t data_mem_wdata_i,
  input  strb_t data_mem_strb_i,
  input  logic  data_mem_we_i,
  output data_t data_mem_rdata_o,

	// Output interrupt signals and taints
  output  logic         int_nmi_o,          // Non-maskable interrupt.
  output  logic         int_external_o,     // External interrupt trigger line.
  output  logic [ 3:0]  int_extern_cause_o, // External interrupt cause code.
  output  logic         int_software_o,     // Software interrupt trigger line.
  output  logic         int_timer_o,        // Timer interrupt trigger line.

  output  logic         int_nmi_o_t0,          // Non-maskable interrupt.
  output  logic         int_external_o_t0,     // External interrupt trigger line.
  output  logic [ 3:0]  int_extern_cause_o_t0, // External interrupt cause code.
  output  logic         int_software_o_t0,     // Software interrupt trigger line.
  output  logic         int_timer_o_t0         // Timer interrupt trigger line.
);

  assign data_mem_gnt_o = 1;

  // Check that the register addresses are distinct.
  initial begin
    assert (ADDRMAP_REG_IRQS != ADDRMAP_REG_IRQ_TAINTS);
    assert (ADDRMAP_REG_IRQS != ADDRMAP_REG_CAUSE);
    assert (ADDRMAP_REG_IRQS != ADDRMAP_REG_CAUSE_TAINT);
    assert (ADDRMAP_REG_IRQS != ADDRMAP_REG_DELAY);
    assert (ADDRMAP_REG_IRQS != ADDRMAP_REG_COMMIT);
    assert (ADDRMAP_REG_IRQ_TAINTS != ADDRMAP_REG_CAUSE);
    assert (ADDRMAP_REG_IRQ_TAINTS != ADDRMAP_REG_CAUSE_TAINT);
    assert (ADDRMAP_REG_IRQ_TAINTS != ADDRMAP_REG_DELAY);
    assert (ADDRMAP_REG_IRQ_TAINTS != ADDRMAP_REG_COMMIT);
    assert (ADDRMAP_REG_CAUSE != ADDRMAP_REG_CAUSE_TAINT);
    assert (ADDRMAP_REG_CAUSE != ADDRMAP_REG_DELAY);
    assert (ADDRMAP_REG_CAUSE != ADDRMAP_REG_COMMIT);
    assert (ADDRMAP_REG_CAUSE_TAINT != ADDRMAP_REG_DELAY);
    assert (ADDRMAP_REG_CAUSE_TAINT != ADDRMAP_REG_COMMIT);
    assert (ADDRMAP_REG_DELAY != ADDRMAP_REG_COMMIT);
  end

  // Registers for the committed signals
  logic         int_nmi_d;
  logic         int_external_d;
  logic [ 3:0]  int_extern_cause_d;
  logic         int_software_d;
  logic         int_timer_d;
  logic         int_nmi_t0_d;
  logic         int_external_t0_d;
  logic [ 3:0]  int_extern_cause_t0_d;
  logic         int_software_t0_d;
  logic         int_timer_t0_d;

  //////////////////////////////
  // Writes
  //////////////////////////////

  logic is_write_req;
  assign is_write_req = data_mem_req_i & data_mem_we_i;

  // Writes to the irq/irqtaint and cause registers
  logic [3:0] next_reg_irqs_d, next_reg_irqs_q; // 3:0 because 4 interrupt types
  logic [3:0] next_reg_irq_taints_d, next_reg_irq_taints_q;
  logic [3:0] next_reg_cause_d, next_reg_cause_q; // 3:0 because dimension of the cause line
  logic [3:0] next_reg_cause_taint_d, next_reg_cause_taint_q;
  assign next_reg_irqs_d        = ((data_mem_addr_i == ADDRMAP_REG_IRQS)        & is_write_req & data_mem_strb_i[0]) ? data_mem_wdata_i[3:0] : next_reg_irqs_q;
  assign next_reg_irq_taints_d  = ((data_mem_addr_i == ADDRMAP_REG_IRQ_TAINTS)  & is_write_req & data_mem_strb_i[0]) ? data_mem_wdata_i[3:0] : next_reg_irq_taints_q;
  assign next_reg_cause_d       = ((data_mem_addr_i == ADDRMAP_REG_CAUSE)       & is_write_req & data_mem_strb_i[0]) ? data_mem_wdata_i[3:0] : next_reg_cause_q;
  assign next_reg_cause_taint_d = ((data_mem_addr_i == ADDRMAP_REG_CAUSE_TAINT) & is_write_req & data_mem_strb_i[0]) ? data_mem_wdata_i[3:0] : next_reg_cause_taint_q;

  // Write to the commit register. is_commit_q is asserted until the commit is done.
  logic is_commit_req;
  assign is_commit_req = (data_mem_addr_i == ADDRMAP_REG_COMMIT) & is_write_req & data_mem_strb_i[0] & |data_mem_wdata_i;

  // Write to the delay
  delay_t reg_delay_d, reg_delay_q;
  always_comb begin
    reg_delay_d = reg_delay_q;
    if ((data_mem_addr_i == ADDRMAP_REG_DELAY) & is_write_req) begin
      if (data_mem_strb_i[0])
        reg_delay_d[7:0]   = data_mem_wdata_i[7:0];
      if (data_mem_strb_i[8])
        reg_delay_d[15:8]  = data_mem_wdata_i[15:8];
      if (data_mem_strb_i[16])
        reg_delay_d[23:16] = data_mem_wdata_i[23:16];
      if (data_mem_strb_i[24])
        reg_delay_d[31:24] = data_mem_wdata_i[31:24];
    end
  end

  // Commit logic
  delay_t curr_countdown_d,   curr_countdown_q;
  logic   is_counting_down_d, is_counting_down_q;
  logic do_commit_now;
  always_comb begin
    do_commit_now = 1'b0;
    is_counting_down_d = is_counting_down_q;
    curr_countdown_d = '0;
    // Check whether should commit now, else start the countdown.
    if (is_commit_req) begin
      if (reg_delay_q == '0)
        do_commit_now = 1'b1;
      else begin
        is_counting_down_d = 1'b1;
        curr_countdown_d   = reg_delay_q;
      end
    end

    // Manage the countdown.
    // If the countdown is being finished, then also commit now.
    if (is_counting_down_q) begin
      if (curr_countdown_q == '0) begin
        curr_countdown_d = '0;
        is_counting_down_d = 1'b0;
        do_commit_now = 1'b1;
      end else begin
        curr_countdown_d = curr_countdown_q-1;
      end
    end

    if (do_commit_now) begin
      $display("Interrupt generator: committing now.");
      int_nmi_d             = next_reg_irqs_q[ID_INT_NMI];
      int_external_d        = next_reg_irqs_q[ID_INT_EXTERNAL];
      int_extern_cause_d    = next_reg_cause_q;
      int_software_d        = next_reg_irqs_q[ID_INT_SOFTWARE];
      int_timer_d           = next_reg_irqs_q[ID_INT_TIMER];
      int_nmi_t0_d          = next_reg_irq_taints_q[ID_INT_NMI];
      int_external_t0_d     = next_reg_irq_taints_q[ID_INT_EXTERNAL];
      int_extern_cause_t0_d = next_reg_cause_taint_q;
      int_software_t0_d     = next_reg_irq_taints_q[ID_INT_SOFTWARE];
      int_timer_t0_d        = next_reg_irq_taints_q[ID_INT_TIMER];
    end else begin
      int_nmi_d             = int_nmi_o;
      int_external_d        = int_external_o;
      int_extern_cause_d    = int_extern_cause_o;
      int_software_d        = int_software_o;
      int_timer_d           = int_timer_o;
      int_nmi_t0_d          = int_nmi_o_t0;
      int_external_t0_d     = int_external_o_t0;
      int_extern_cause_t0_d = int_extern_cause_o_t0;
      int_software_t0_d     = int_software_o_t0;
      int_timer_t0_d        = int_timer_o_t0;
    end
  end

  //////////////////////////////
  // Reads
  //////////////////////////////

  logic is_read_req;
  assign is_read_req = data_mem_req_i & data_mem_we_i;

  always_comb begin
    data_mem_rdata_o = '0;
    if (is_read_req) begin
      case (data_mem_addr_i)
        ADDRMAP_REG_IRQS: data_mem_rdata_o = next_reg_irqs_q;
        ADDRMAP_REG_IRQ_TAINTS: data_mem_rdata_o = next_reg_irq_taints_q;
        ADDRMAP_REG_CAUSE: data_mem_rdata_o = next_reg_cause_q;
        ADDRMAP_REG_CAUSE_TAINT: data_mem_rdata_o = next_reg_cause_taint_q;
        ADDRMAP_REG_DELAY: data_mem_rdata_o = reg_delay_q;
        ADDRMAP_REG_COMMIT: data_mem_rdata_o = is_counting_down_q;
        default: data_mem_rdata_o = '0;
      endcase
    end
  end

  //////////////////////////////
  // Registers
  //////////////////////////////

  always_ff @(posedge clk_i) begin
    if (~rst_ni) begin
      next_reg_irqs_q        <= '0;
      next_reg_irq_taints_q  <= '0;
      next_reg_cause_q       <= '0;
      next_reg_cause_taint_q <= '0;
      reg_delay_q            <= '0;
      int_nmi_o              <= '0;
      int_external_o         <= '0;
      int_extern_cause_o     <= '0;
      int_software_o         <= '0;
      int_timer_o            <= '0;
      int_nmi_o_t0           <= '0;
      int_external_o_t0      <= '0;
      int_extern_cause_o_t0  <= '0;
      int_software_o_t0      <= '0;
      int_timer_o_t0         <= '0;
      curr_countdown_q       <= '0;
      is_counting_down_q     <= '0;
    end else begin
      next_reg_irqs_q        <= next_reg_irqs_d;
      next_reg_irq_taints_q  <= next_reg_irq_taints_d;
      next_reg_cause_q       <= next_reg_cause_d;
      next_reg_cause_taint_q <= next_reg_cause_taint_d;
      reg_delay_q            <= reg_delay_d;
      int_nmi_o              <= int_nmi_d;
      int_external_o         <= int_external_d;
      int_extern_cause_o     <= int_extern_cause_d;
      int_software_o         <= int_software_d;
      int_timer_o            <= int_timer_d;
      int_nmi_o_t0           <= int_nmi_t0_d;
      int_external_o_t0      <= int_external_t0_d;
      int_extern_cause_o_t0  <= int_extern_cause_t0_d;
      int_software_o_t0      <= int_software_t0_d;
      int_timer_o_t0         <= int_timer_t0_d;
      curr_countdown_q       <= curr_countdown_d;
      is_counting_down_q     <= is_counting_down_d;
    end
  end

  //////////////////////////////
  // Some debug prints
  //////////////////////////////

  always_comb begin
    if ((data_mem_addr_i == ADDRMAP_REG_IRQS)        & is_write_req & data_mem_strb_i[0])
      $display("Interrupt generator: wrote to REG_IRQS.");
    if ((data_mem_addr_i == ADDRMAP_REG_IRQ_TAINTS)  & is_write_req & data_mem_strb_i[0])
      $display("Interrupt generator: wrote to REG_IRQ_TAINTS.");
    if ((data_mem_addr_i == ADDRMAP_REG_CAUSE)       & is_write_req & data_mem_strb_i[0])
      $display("Interrupt generator: wrote to REG_CAUSE.");
    if ((data_mem_addr_i == ADDRMAP_REG_CAUSE_TAINT) & is_write_req & data_mem_strb_i[0])
      $display("Interrupt generator: wrote to REG_CAUSE_TAINT.");
    if ((data_mem_addr_i == ADDRMAP_REG_DELAY)       & is_write_req & |data_mem_strb_i)
      $display("Interrupt generator: wrote to REG_DELAY.");
    if ((data_mem_addr_i == ADDRMAP_REG_COMMIT)      & is_write_req & data_mem_strb_i[0])
      $display("Interrupt generator: wrote to REG_COMMIT.");
  end
endmodule
