/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package f32ghidra;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class F32GhidraLoader extends AbstractProgramWrapperLoader {

	@Override
	public String getName() {
    return "AMD F32 Loader (new)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("F32:LE:64:default", "default"), true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
    FlatProgramAPI api = new FlatProgramAPI(program, monitor);
    // Initial header size
    long hdr_size = 0x100;
    long footer_size = 0;
    byte[] hdr = provider.readBytes(0, hdr_size);
    ByteBuffer buff = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN);
    // if major version >= 9 (guess, maybe older are weird too) there is what looks like header for after normal hedaer for kernel and footer with
    // what looks like digital signature (512 bytes, high entropy)
    if ((buff.getInt(12) & 0xFFFFL) >= 9) {
      hdr_size = 0x200;
      footer_size = 512;
      hdr = provider.readBytes(0, hdr_size);
      buff = ByteBuffer.wrap(hdr).order(ByteOrder.LITTLE_ENDIAN);
    }
    long fw_len = (buff.getInt(20) & 0x00000000ffffffffL) - footer_size;
    long ucode_len = fw_len & ~0xFFF;
    long jumptable_len = fw_len & 0xFFF;
    Memory mem = program.getMemory();
    InputStream inStream = provider.getInputStream(0);
    try {
      // Create header
      mem.createInitializedBlock("header", api.toAddr("header:0x0"), inStream, hdr_size, monitor, false);
      // Mark every byte in header as byte so ghidra won't attempt to disassemble it
      for (long i = 0; i < hdr_size; i++) {
        api.createByte(api.toAddr("header:0x0").add(i));
      }
      // UCode is main thing
      mem.createInitializedBlock("ucode", api.toAddr("ucode:0x0"), inStream, ucode_len, monitor, false);
      // Mark start function.
      api.createFunction(api.toAddr("ucode:0x0"), "start");
      // Jumptable at the end - it will be marked as dwords later
      mem.createInitializedBlock("jumptable", api.toAddr("jumptable:0x0"), inStream, jumptable_len, monitor, false);
    } catch (Exception e) {
      e.printStackTrace();
      throw new IOException("load failed");
    }
    if (jumptable_len % 4 != 0) {
      throw new IOException("jumptable size isn't the multiple of 4");
    }

    Dictionary<Integer, String> dict = pktdefs();

    // Parse jumptable
    for (long jtab_address = hdr_size + ucode_len; jtab_address < hdr_size + ucode_len + jumptable_len; jtab_address += 4) {
      ByteBuffer je = ByteBuffer.allocate(8);
      je.put(provider.readBytes(jtab_address, 4));
      je.put(new byte[4]);
      long jel = je.order(ByteOrder.LITTLE_ENDIAN).getLong(0) & 0x00000000ffffffffL;
      // jumptable entry is 4 bytes, high 2 bits are packet number, low 2 bits are where to jump (div 4)
      long handler = (jel & 0xFFFFl) * 4;
      long packet_id = (jel >> 16);
      // Get name
      String name = dict.get((int) packet_id);
      if (name == null) {
        name = String.format("PKT_0x%02X", packet_id);
      } else {
        name = String.format("PKT_%s", name);
      }
      try {
        api.createFunction(api.toAddr("ucode:0x0").add(handler), name);
      } catch (Exception e) {
        e.printStackTrace();
        throw new IOException("failed to add label to packet handler from jumptable");
      }
    }
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		return super.validateOptions(provider, loadSpec, options, program);
	}

	public Dictionary<Integer, String> pktdefs() {

    Dictionary<Integer, String> dict = new Hashtable<>();
    // java being cringe. This should be loaded from file
    dict.put(0x10, "NOP");
    dict.put(0x11, "SET_BASE");
    dict.put(0x12, "CLEAR_STATE");
    dict.put(0x13, "INDEX_BUFFER_SIZE");
    dict.put(0x15, "DISPATCH_DIRECT");
    dict.put(0x16, "DISPATCH_INDIRECT");
    dict.put(0x17, "INDIRECT_BUFFER_END");
    dict.put(0x1D, "ATOMIC_GDS");
    dict.put(0x1E, "ATOMIC_MEM");
    dict.put(0x1F, "OCCLUSION_QUERY");
    dict.put(0x20, "SET_PREDICATION");
    dict.put(0x21, "REG_RMW");
    dict.put(0x22, "COND_EXEC");
    dict.put(0x23, "PRED_EXEC");
    dict.put(0x24, "DRAW_INDIRECT");
    dict.put(0x25, "DRAW_INDEX_INDIRECT");
    dict.put(0x26, "INDEX_BASE");
    dict.put(0x27, "DRAW_INDEX_2");
    dict.put(0x28, "CONTEXT_CONTROL");
    dict.put(0x2A, "INDEX_TYPE");
    dict.put(0x2B, "DRAW_INDEX");
    dict.put(0x2C, "DRAW_INDIRECT_MULTI");
    dict.put(0x2D, "DRAW_INDEX_AUTO");
    dict.put(0x2E, "DRAW_INDEX_IMMD");
    dict.put(0x2F, "NUM_INSTANCES");
    dict.put(0x30, "DRAW_INDEX_MULTI_AUTO");
    dict.put(0x32, "INDIRECT_BUFFER_32");
    dict.put(0x33, "INDIRECT_BUFFER_CONST");
    dict.put(0x34, "STRMOUT_BUFFER_UPDATE");
    dict.put(0x35, "DRAW_INDEX_OFFSET_2");
    dict.put(0x36, "DRAW_PREAMBLE");
    dict.put(0x37, "WRITE_DATA");
    dict.put(0x38, "DRAW_INDEX_INDIRECT_MULTI");
    dict.put(0x39, "MEM_SEMAPHORE");
    dict.put(0x3A, "MPEG_INDEX");
    dict.put(0x3B, "COPY_DW");
    dict.put(0x3C, "WAIT_REG_MEM");
    dict.put(0x3D, "MEM_WRITE");
    dict.put(0x3F, "INDIRECT_BUFFER_3F");
    dict.put(0x40, "COPY_DATA");
    dict.put(0x41, "CP_DMA");
    dict.put(0x42, "PFP_SYNC_ME");
    dict.put(0x43, "SURFACE_SYNC");
    dict.put(0x44, "ME_INITIALIZE");
    dict.put(0x45, "COND_WRITE");
    dict.put(0x46, "EVENT_WRITE");
    dict.put(0x47, "EVENT_WRITE_EOP");
    dict.put(0x48, "EVENT_WRITE_EOS");
    dict.put(0x49, "RELEASE_MEM");
    dict.put(0x4A, "PREAMBLE_CNTL");
    dict.put(0x50, "DMA_DATA");
    dict.put(0x57, "ONE_REG_WRITE");
    dict.put(0x58, "ACQUIRE_MEM");
    dict.put(0x59, "REWIND");
    dict.put(0x5E, "LOAD_UCONFIG_REG");
    dict.put(0x5F, "LOAD_SH_REG");
    dict.put(0x60, "LOAD_CONFIG_REG");
    dict.put(0x61, "LOAD_CONTEXT_REG");
    dict.put(0x68, "SET_CONFIG_REG");
    dict.put(0x69, "SET_CONTEXT_REG");
    dict.put(0x6A, "SET_ALU_CONST");
    dict.put(0x6B, "SET_BOOL_CONST");
    dict.put(0x6C, "SET_LOOP_CONST");
    dict.put(0x6D, "SET_RESOURCE");
    dict.put(0x6E, "SET_SAMPLER");
    dict.put(0x6F, "SET_CTL_CONST");
    dict.put(0x73, "SET_CONTEXT_REG_INDIRECT");
    dict.put(0x76, "SET_SH_REG");
    dict.put(0x77, "SET_SH_REG_OFFSET");
    dict.put(0x78, "SET_QUEUE_REG");
    dict.put(0x79, "SET_UCONFIG_REG");
    dict.put(0x7D, "SCRATCH_RAM_WRITE");
    dict.put(0x7E, "SCRATCH_RAM_READ");
    dict.put(0x80, "LOAD_CONST_RAM");
    dict.put(0x81, "WRITE_CONST_RAM");
    dict.put(0x83, "DUMP_CONST_RAM");
    dict.put(0x84, "INCREMENT_CE_COUNTER");
    dict.put(0x85, "INCREMENT_DE_COUNTER");
    dict.put(0x86, "WAIT_ON_CE_COUNTER");
    dict.put(0x88, "WAIT_ON_DE_COUNTER_DIFF");
    dict.put(0x8B, "SWITCH_BUFFER");

    return dict;
	}
}
