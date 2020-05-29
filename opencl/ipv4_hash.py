#!/usb/bin/env 

import numpy as np
import pyopencl as cl

PROGRAM_FILE = "ipv4_hash.cl"
TASK_NB = 2**32-1

def main():
  ctx = cl.create_some_context()
  queue = cl.CommandQueue(ctx)
  with open(PROGRAM_FILE) as prg_file:
    prg = cl.Program(ctx, prg_file.read()).build()

  res_g = cl.Buffer(ctx, cl.mem_flags.WRITE_ONLY, 100)

  #prg.ipv4_hash(queue,(TASK_NB,), None, res_g)
  prg.ipv4_hash(queue,(TASK_NB,), None, res_g)
  queue.finish()

  #res_np = np.empty(10, np.float32)
  #cl.enqueue_copy(queue, res_np, res_g)

  #print(res_np)

if __name__ == "__main__":
    main()

