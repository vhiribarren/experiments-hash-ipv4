#!/usr/bin/env python3

import numpy as np
import pyopencl as cl


TARGETS_NP = np.array([ 
    [0x19e36255, 0x972107d4, 0x2b8cecb7, 0x7ef5622e, 0x842e8a50, 0x778a6ed8, 0xdd1ce947, 0x32daca9e], # 0.0.0.0
    [0x52ab14a4, 0x8cb94196, 0x3a498fae, 0xfd02b109, 0x0ebfccfe, 0x47f07d54, 0x52628d82, 0x80b60154], # 1.0.0.0
    [0x12ca17b4, 0x9af22894, 0x36f303e0, 0x166030a2, 0x1e525d26, 0x6e209267, 0x433801a8, 0xfd4071a0], # 127.0.0.1
    [0x37d7a806, 0x04871e57, 0x9850a658, 0xc7add2ae, 0x7557d0c6, 0xabcc9b31, 0xecddc442, 0x4207eba3], # 192.168.0.1
    [0xc4249e36, 0x619119f4, 0xcaee1035, 0xf63e28b8, 0x0809a6e7, 0x643feb27, 0x305a84b0, 0x129a12d0], # 254.0.0.1
    [0xf45462bf, 0x3cd12ea2, 0xb347f32f, 0x6c4d0a0d, 0x36e01694, 0xde332b30, 0x7af90d42, 0x951c5bd6], # 255.255.255.255
  ], dtype=np.uint32 )

PROGRAM_FILE = "ipv4_hash.cl"
WORKITEM_TOTAL = 2**32
WORKITEM_ITER = 1

def list_cap():
  for platform in cl.get_platforms():
    for device in platform.get_devices():    
        print(f"")

def main():
  ctx = cl.create_some_context()
  queue = cl.CommandQueue(ctx)
  with open(PROGRAM_FILE) as prg_file:
    prg = cl.Program(ctx, prg_file.read()).build()

  targets_buf = cl.Buffer(ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=TARGETS_NP)

  results_np = np.zeros(np.shape(TARGETS_NP)[0], dtype=np.uint32)
  results_buf = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY, results_np.nbytes)
  cl.enqueue_fill_buffer(queue, results_buf, np.uint32(0), 0, np.dtype(np.uint32).itemsize*np.shape(results_np)[0], None)
  success_np = np.zeros(np.shape(TARGETS_NP)[0], dtype=np.uint32)
  success_buf = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY, success_np.nbytes)
  cl.enqueue_fill_buffer(queue, success_buf, np.uint32(0), 0, np.dtype(np.uint32).itemsize*np.shape(success_np)[0], None)
  #prg.ipv4_hash(queue, (WORKITEM_NB,), (WORKITEM_PER_GROUP,), targets_buf, success_buf, results_buf)
  prg.ipv4_hash(queue, (WORKITEM_TOTAL//WORKITEM_ITER,), None, np.uint32(WORKITEM_ITER), targets_buf, success_buf, results_buf)
 
  cl.enqueue_copy(queue, results_np, results_buf)
 
  cl.enqueue_copy(queue, success_np, success_buf)
  #queue.finish()


  print(success_np)
  print(results_np)


if __name__ == "__main__":
    main()

