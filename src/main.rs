#![feature(vec_remove_item)]

extern crate xmas_elf;
extern crate capstone;

use std::env;
use std::process::exit;
use std::fs::File;
use std::io::Read;
use std::io;
use xmas_elf::ElfFile;
use xmas_elf::sections::SectionHeader;
use xmas_elf::program::ProgramHeader;
use std::ops::Bound::Included;
use std::ops::Bound::Excluded;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86InsnGroup;
use capstone::arch::ArchOperand;
use capstone::prelude::*;

use std::collections::BTreeMap;

struct InstructionSpan {
	address: u64,
	span: u32
}

struct Disassembly<'a> {
	elf: ElfFile<'a>,
	engine: Capstone<'a>,
	targets: BTreeMap<u64, InstructionSpan>,
	instructions: BTreeMap<u64, InstructionSpan>,
	max_insn_addr: u64,
	min_insn_addr: u64,
	file: String
}

impl<'a> Disassembly<'a> {

	fn print_instructions(&self) {
		for k in self.instructions.keys() {
			println!("0x{:x}", k);
		}
	}

	fn new(file: String, bytes: &'a Vec<u8>) -> Disassembly<'a> {
		let mut d: Disassembly;
		let mut capstone_engine = Capstone::new()
			.x86()
			.mode(arch::x86::ArchMode::Mode64)
			.build()
			.expect("Oops: Could not create the capstone engine.");
		capstone_engine.set_detail(true);

		d = Disassembly{elf: ElfFile::new(&bytes).unwrap(),
			engine: capstone_engine,
			targets: BTreeMap::new(),
			instructions: BTreeMap::new(),
			file: file,
			max_insn_addr: 0,
			min_insn_addr: 0
		};

		for s in d.elf.section_iter() {
			if let Ok(sh) = s.get_name(&d.elf) {
				if sh == ".text" {
					d.min_insn_addr = s.address();
					d.max_insn_addr = s.address() + s.size();
				}
			}
		}

		let entry_point = d.elf.header.pt2.entry_point();
		d.targets.insert(entry_point, InstructionSpan{address: entry_point,span:0});
		return d;
	}

	fn next_target(&self, address: u64) -> u64 {
		match self.targets
		          .range((Excluded(address+1),Included(self.max_insn_addr)))
		          .nth(0) {
			Some(t) => *(t.0),
			None => self.max_insn_addr
		}
	}

	fn instruction_at(&self, addr: &u64) -> bool {
		match self.instructions.get(&addr) {
			Some(_) => true,
			None => false
		}
	}

	fn disassemble(&mut self) {
		let mut targets_to_consider = Vec::<u64>::new();
		targets_to_consider.push(self.elf.header.pt2.entry_point());
		while !targets_to_consider.is_empty() {
			let target = targets_to_consider.pop().unwrap();
			let next_target: u64;

			/*
			 * Is there already an instruction at exactly this address?
			 * Yes: skip.
			 */
			if self.instruction_at(&target) {
				continue;
			}

			next_target = self.next_target(target);

			println!("Disassembling from 0x{:x} to 0x{:x}", target, next_target);

			/*
			 * Add this target to self.targets.
			 */
			self.targets.insert(target, InstructionSpan{address: target, span:5});

			/*
			 * Invalidate between target and next_target
			 */
			for k in self.targets.keys() {
				if k >= &target && k <= &next_target {
					println!("Invalidating 0x{:x}", k);
				}
			}


			if let Ok(insns)=
				self.engine.disasm_all(&self.elf.input[target as usize..],
				                       target) {
				for i in insns.iter() {
					if i.address() >= next_target {
						println!("Stopping disassembly at the next_target address.");
						break;
					}
					/*
					 * Add this instruction's address and span to the tentative
					 * list of instructions.
					 */
					self.instructions.insert(i.address(),
					                         InstructionSpan{address: i.address(),
					                                         span: i.bytes().len() as u32
					                                        });
					/*
					 * If this instruction is precisely at some place that
					 * we are supposed to disassemble in the future, wipe
					 * out that future target because it will get the 
					 * exact same thing that we are getting now.
					 */
					if let Ok(idx) = targets_to_consider.binary_search(&i.address()) {
						println!("Was going to consider 0x{:x} but already disassembled.",
						         i.address());
						targets_to_consider.remove_item(&(idx as u64));
						continue;
					}

					/*
					 * Get the instruction's target, if it has one.
					 */
					if let Some(insn_target) = self.insn_target(&i) {
						/*
						 * Skip this if it's already in our known targets.
						 */
						if let Some(_) = self.targets.get(&insn_target) {
							println!("0x{:x} is already a found target.", insn_target);
							continue;
						}

						/*
						 * No special handling if we are already planning
						 * to consider this target.
						 */
						if targets_to_consider.contains(&insn_target) {
							println!("0x{:x} is already set to be considered.", insn_target);
							continue;
						}

						/*
						 * If this targets an instruction that is already
						 * correctly disassembled, it cannot change subsequent
						 * disassembly. So, no need to look at it again. Just
						 * add to the list of targets.
						 */
						if self.instruction_at(&insn_target) {
							println!("0x{:x} matches an instruction.", insn_target);
							self.instructions.insert(insn_target,
							                         InstructionSpan{address: insn_target,
							                                         span: 5});	
							continue;
						}

						/*
						 * None of the above? We found a target location 
						 * that needs to be considered!
						 */
						println!("Adding 0x{:x} as a target to consider.", insn_target);
						targets_to_consider.push(insn_target);
					}
				}
			}
		}
	}

	fn insn_target(&self, insn: &capstone::Insn) -> Option<u64> {
		match self.engine.insn_detail(insn) {
			Ok(details) => {
				/*
				 * Look for all the groups and find out if any of them
				 * are JUMP or CALL.
				 */
				for group in details.groups() {
					if group == capstone::InsnGroupId(X86InsnGroup::X86_GRP_JUMP as u8) ||
					   group == capstone::InsnGroupId(X86InsnGroup::X86_GRP_CALL as u8) {
						/*
						 * Look for the immediate operand in the list of all
						 * operands.
						 */
						for op in details.arch_detail().operands() {
							if let ArchOperand::X86Operand(x86op) = op {
								if let X86OperandType::Imm(target) = x86op.op_type {
									/*
									 * That's the target, so let's return it.
									 */
									return Some(target as u64);
								}
							}
						}
					}
				}
				/*
				 * This is not a JUMP or CALL so it does not have a
				 * target.
				 */
				return None;
			},
			/*
			 * There are no details available for this instruction.
			 */
			Err(_) => None
		}
	}
}

fn open_file(path: &String) -> Result<Vec<u8>, io::Error> {
	let fm = File::open(path);
	let mut buf = Vec::new();

	match fm {
		Ok(mut f) => {
			match f.read_to_end(&mut buf) {
				Ok(_) => Ok(buf),
				Err(e) => Err(e)
			}
		},
		Err(e) => Err(e)
	}
}

fn usage(me: String) {
	println!("Usage: {} [filename]", me);
}

fn main() {
	let mut args = env::args();
	let me: String;
	let path: String;
	let contents: Vec<u8>;
	let mut disassembly: Disassembly;

	me = args.next().unwrap();

	if let Some(p) = args.next() {
		path = p;
	} else {
		usage(me);
		exit(-1);
	}

	contents = open_file(&path).unwrap();
	disassembly = Disassembly::new(path, &contents);
	disassembly.disassemble();
	disassembly.print_instructions();
}
