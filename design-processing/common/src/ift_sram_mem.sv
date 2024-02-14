// Copyright Flavien Solt, ETH Zurich.
// Licensed under the General Public License, Version 3.0, see LICENSE for details.
// SPDX-License-Identifier: GPL-3.0-only

// Conservative SRAM module with taints.

module ift_sram_mem #(
  parameter int Width           = 64, // bit
  parameter int Depth           = 1 << 8,
  parameter int NumTaints       = 1,

  parameter bit PreloadELF = 1,
  parameter bit PreloadTaints = 1,
  parameter logic [63:0] RelocateRequestUp = 0,

  // Derived parameters.
  localparam int WidthBytes = Width >> 3,
  localparam int Aw         = $clog2(Depth),
  localparam bit [Aw-1:0] AddrMask = {Aw{1'b1}}
) (
  input  logic             clk_i,
  input  logic             rst_ni,

  input  logic             req_i,
  input  logic             write_i,
  input  logic [Aw-1:0]    addr_i,
  input  logic [Width-1:0] wdata_i,
  input  logic [Width-1:0] wmask_i,
  output logic [Width-1:0] rdata_o, // Read data. Data is returned one cycle after req_i is high.

  input  logic [NumTaints-1:0]            req_i_taint,
  input  logic [NumTaints-1:0]            write_i_taint,
  input  logic [NumTaints-1:0][Aw-1:0]    addr_i_taint,
  input  logic [NumTaints-1:0][Width-1:0] wdata_i_taint,
  input  logic [NumTaints-1:0][Width-1:0] wmask_i_taint,
  output logic [NumTaints-1:0][Width-1:0] rdata_o_taint // Read data. Data is returned one cycle after req_i is high.
);

  initial begin
    assert(NumTaints == 1);
  end

  // Taint the full sram if a write occurs with a tainted address.
  logic [NumTaints-1:0][Width-1:0] rdata_o_taint_before_conservative;
  for (genvar taint_id = 0; taint_id < NumTaints; taint_id++) begin : gen_taints_conservative
    logic is_mem_fully_tainted_d, is_mem_fully_tainted_q;
    assign is_mem_fully_tainted_d = is_mem_fully_tainted_q | ((req_i | req_i_taint[taint_id]) & (write_i | write_i_taint[taint_id]) & |((wmask_i | wmask_i_taint[taint_id]) & addr_i_taint[taint_id]));
    always_ff @(posedge clk_i, negedge rst_ni) begin
      if (~rst_ni) begin
        is_mem_fully_tainted_q <= '0;
      end else begin
        is_mem_fully_tainted_q <= is_mem_fully_tainted_d;
      end
    end

    // Remember whether the request was made with a tainted address. Sensitivity to reset is important.
    logic was_req_addr_tainted_d, was_req_addr_tainted_q;
    assign was_req_addr_tainted_d = |addr_i_taint[taint_id] | req_i_taint[taint_id] | (req_i & write_i_taint[taint_id]);
    always_ff @(posedge clk_i, negedge rst_ni) begin
      if (~rst_ni) begin
        was_req_addr_tainted_q <= '0;
      end else begin
        was_req_addr_tainted_q <= was_req_addr_tainted_d;
      end
    end

    // Taint the read data if the addr was tainted.
    // assign rdata_o_taint[taint_id] = rdata_o_taint_before_conservative[taint_id] | {(Width){was_req_addr_tainted_q | is_mem_fully_tainted_q}};
    assign rdata_o_taint[taint_id] = rdata_o_taint_before_conservative[taint_id];

  end

  logic [Width-1:0]    mem [bit [31:0]];
  logic [Width-1:0]    mem_taints [bit [31:0]];

  //
  // DPI
  //

  import "DPI-C" function read_elf(input string filename);
  import "DPI-C" function byte get_section(output longint address, output longint len);
  import "DPI-C" context function byte read_section(input longint address, inout byte buffer[]);

  import "DPI-C" function init_taint_vectors(input longint num_taints);
  import "DPI-C" function init_taint_data_vectors(input longint num_taints);
  import "DPI-C" function read_taints(input string filename, input int word_width_bytes);
  import "DPI-C" function read_taints_and_data(input string filename, input int word_width_bytes);
  import "DPI-C" context function byte get_next_taint_word(input longint taint_id, output longint word_address, output byte buffer[]);
  import "DPI-C" context function byte get_next_taint_and_data_word(input longint taint_id, output longint word_address, output byte tbuffer[], output byte dbuffer[]);
  import "DPI-C" function string Get_SRAM_ELF_object_filename();
  import "DPI-C" function string Get_SRAM_TaintsPath();
  import "DPI-C" function void reset_section_index();

  export "DPI-C" function _reset_memory;
  export "DPI-C" function _reset_memory_t;
  export "DPI-C" function _dump_mem;



  localparam int unsigned PreloadBufferSize = 100000000;
  byte preload_buffer[PreloadBufferSize];

  function void _reset_memory();
    begin
      string binary = Get_SRAM_ELF_object_filename();
      longint section_addr, section_len;
      reset_section_index();
      // $display("MEMORY RESET");
      mem.delete();
      preload_buffer = '{default: '0};
      void'(read_elf(binary));
      while (get_section(section_addr, section_len)) begin
        automatic int num_words = (section_len+(WidthBytes-1))/WidthBytes;

        assert(num_words*WidthBytes <= PreloadBufferSize);
        void'(read_section(section_addr, preload_buffer));

        for (int i = 0; i < num_words; i++) begin
          automatic logic [WidthBytes-1:0][7:0] word = '0;
          for (int j = 0; j < WidthBytes; j++) begin
            word[j] = preload_buffer[i*WidthBytes+j];
          end
          if (|word)
            // $display("Writing ELF word to SRAM addr %x: %x", (AddrMask&section_addr)/WidthBytes+i, word);
          mem[(AddrMask&section_addr)/WidthBytes+i] = word;
        end
      end
    end  
  endfunction : _reset_memory

  function void _reset_memory_t(); // resets only taints
    begin
      string binary = Get_SRAM_TaintsPath();
      longint word_addr;
      byte unsigned tbuffer[Width >> 3]; // The unsigned is important, else sign extension expands to the whole word
      byte unsigned dbuffer[Width >> 3]; // The unsigned is important, else sign extension expands to the whole word
      void'(init_taint_data_vectors(NumTaints));
      void'(read_taints_and_data(binary, Width >> 3));
      mem_taints.delete();
      assert(mem_taints.size() == 0);

      for (int taint_id = 0; taint_id < NumTaints; taint_id++) begin 
        while (get_next_taint_and_data_word(taint_id, word_addr, tbuffer, dbuffer)) begin
          mem_taints[(AddrMask >> $clog2(WidthBytes))&word_addr] = {WidthBytes{1'h0}};

          // if(mem[(AddrMask >> $clog2(WidthBytes))&word_addr][31:0] != 'hDEADBEEF) begin
          //   $error("Overwriting wrong region: Holds 0x%x instead of 0xdeadbeef at 0x%x", mem[(AddrMask >> $clog2(WidthBytes))&word_addr][31:0], (AddrMask >> $clog2(WidthBytes))&word_addr);
          // end

          // $display("Overwriting %x at %x", mem[(AddrMask >> $clog2(WidthBytes))&word_addr], (AddrMask >> $clog2(WidthBytes))&word_addr);

          // mem[(AddrMask >> $clog2(WidthBytes))&word_addr] = {WidthBytes{1'h0}};
          // assert(mem[(AddrMask >> $clog2(WidthBytes))&word_addr] == {WidthBytes{1'h0}});


          // $display("WidthByte %x", WidthBytes);

          for (int byte_id_in_word = 0; byte_id_in_word < WidthBytes; byte_id_in_word++) begin
            automatic bit [Width-1:0] interm_taint_word = tbuffer[byte_id_in_word] << (byte_id_in_word << 3);
            // automatic bit [Width-1:0] interm_data_word = dbuffer[byte_id_in_word] << (byte_id_in_word << 3);
            mem_taints[(AddrMask >> $clog2(WidthBytes))&word_addr] |= interm_taint_word;
            // mem[(AddrMask >> $clog2(WidthBytes))&word_addr] |= interm_data_word;
            // $display("Tainting %x with %x", (AddrMask >> $clog2(WidthBytes))&word_addr, interm_taint_word);
          end
          // $display("Adding taint word SRAM addr %x (filtered: %x): %x, storing %x", word_addr, (AddrMask >> $clog2(WidthBytes))&word_addr, mem_taints[(AddrMask >> $clog2(WidthBytes))&word_addr], mem[(AddrMask >> $clog2(WidthBytes))&word_addr]);

        end
      end
    end
  endfunction : _reset_memory_t


  function void _dump_mem();
    begin
      longint section_addr, section_len;
      reset_section_index();
      $display("MEMORY DUMP");
      while (get_section(section_addr, section_len)) begin
        automatic int num_words = (section_len+(WidthBytes-1))/WidthBytes;
        for (int i = 0; i < num_words; i++) begin
          $display("Memory dump at %x: %x", AddrMask&section_addr/WidthBytes+i, mem[(AddrMask&section_addr)/WidthBytes+i]);
        end
      end
    end  
  endfunction : _dump_mem


  initial begin // Load the binary into memory.
    if (PreloadELF) begin
      string binary = Get_SRAM_ELF_object_filename();
      longint section_addr, section_len;
      void'(read_elf(binary));
      while (get_section(section_addr, section_len)) begin
        automatic int num_words = (section_len+(WidthBytes-1))/WidthBytes;

        // buffer = new [num_words*WidthBytes];
        assert(num_words*WidthBytes <= PreloadBufferSize);
        void'(read_section(section_addr, preload_buffer));

        for (int i = 0; i < num_words; i++) begin
          automatic logic [WidthBytes-1:0][7:0] word = '0;
          for (int j = 0; j < WidthBytes; j++) begin
            word[j] = preload_buffer[i*WidthBytes+j];
          end
          if (|word)
            // $display("Writing ELF word to SRAM addr %x: %x", (AddrMask&section_addr)/WidthBytes+i, word);
          mem[(AddrMask&section_addr)/WidthBytes+i] = word;
        end
      end
    end
  end

  initial begin // Load the taint into memory.
    if (PreloadTaints) begin
      string binary = Get_SRAM_TaintsPath();
      longint word_addr;
      byte unsigned tbuffer[Width >> 3]; // The unsigned is important, else sign extension expands to the whole word
      byte unsigned dbuffer[Width >> 3]; // The unsigned is important, else sign extension expands to the whole word
      void'(init_taint_data_vectors(NumTaints));
      void'(read_taints_and_data(binary, Width >> 3));
      for (int taint_id = 0; taint_id < NumTaints; taint_id++) begin
        while (get_next_taint_and_data_word(taint_id, word_addr, tbuffer, dbuffer)) begin
          if (!mem_taints.exists((AddrMask >> $clog2(WidthBytes))&word_addr))
            mem_taints[(AddrMask >> $clog2(WidthBytes))&word_addr] = '0;
          for (int byte_id_in_word = 0; byte_id_in_word < WidthBytes; byte_id_in_word++) begin
            automatic bit [Width-1:0] interm_taint_word = tbuffer[byte_id_in_word] << (byte_id_in_word << 3);
            mem_taints[(AddrMask >> $clog2(WidthBytes))&word_addr] |= interm_taint_word;
            // Write zeros to the corresponding memory
`ifdef MODELSIM
            if ($isunknown(mem[(AddrMask >> $clog2(WidthBytes))&word_addr]))
              mem[(AddrMask >> $clog2(WidthBytes))&word_addr] = '0;
`endif
          end
          $display("Adding taint word SRAM addr %x (filtered: %x): %x, storing %x", word_addr, (AddrMask >> $clog2(WidthBytes))&word_addr, mem_taints[(AddrMask >> $clog2(WidthBytes))&word_addr], mem[word_addr]);
        end
      end
    end
  end

  //
  //  Data
  //

  always_ff @(posedge clk_i) begin
		if (req_i) begin
      if (write_i) begin
          rdata_o <= '0;
          for (int i = 0; i < Width; i = i + 1)
            if (wmask_i[i])
              mem[AddrMask & (RelocateRequestUp | addr_i)][i] = wdata_i[i];
      end
      else begin
          if (mem.exists(AddrMask & (RelocateRequestUp | addr_i))) begin
            rdata_o <= mem[AddrMask & (RelocateRequestUp | addr_i)];
            // $display("INFO: Memory known at address %h: %x", AddrMask & (RelocateRequestUp | addr_i), mem[AddrMask & (RelocateRequestUp | addr_i)]);
            if(mem_taints[AddrMask & (RelocateRequestUp | addr_i)]) begin
              // $display("INFO: Memory at address %h is tainted: %x", AddrMask & (RelocateRequestUp | addr_i), mem_taints[AddrMask & (RelocateRequestUp | addr_i)]);
            end
          end
          else begin
            rdata_o <= 0;
            // $display("WARNING: Memory unknown at address %h.", AddrMask & (RelocateRequestUp | addr_i));
          end
      end
    end
    else
      rdata_o <= '0;
  end

  for (genvar taint_id = 0; taint_id < NumTaints; taint_id++) begin : gen_taints

    always_ff @(posedge clk_i) begin
      if (req_i) begin
        if (write_i) begin
          rdata_o_taint_before_conservative[taint_id] = '0;
          for (int i = 0; i < Width; i = i + 1)
            if (wmask_i[i]) begin
              if (!mem_taints.exists(AddrMask & (RelocateRequestUp | addr_i)))
                mem_taints[AddrMask & (RelocateRequestUp | addr_i)] = '0;
              // mem_taints[AddrMask & (RelocateRequestUp | addr_i)][i] = wdata_i_taint[taint_id][i] | wdata_i_taint[taint_id][i];
              mem_taints[AddrMask & (RelocateRequestUp | addr_i)][i] |= wdata_i_taint[taint_id][i]; // add taint to memory with possibly existing taint mask at address

            end
        end
        else
          if (mem_taints.exists(AddrMask & (RelocateRequestUp | addr_i)))
            rdata_o_taint_before_conservative[taint_id] = mem_taints[AddrMask & (RelocateRequestUp | addr_i)];
          else
            rdata_o_taint_before_conservative[taint_id] = '0;
      end else
        rdata_o_taint_before_conservative[taint_id] = '0;
    end
  end : gen_taints

endmodule
