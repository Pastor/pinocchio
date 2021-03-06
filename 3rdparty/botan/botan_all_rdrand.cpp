/*
* Botan 2.12.0 Amalgamation
* (C) 1999-2018 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan_all.h"
#include "botan_all_internal.h"

#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC target ("rdrnd")
#endif
/*
* RDRAND RNG
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if !defined(BOTAN_USE_GCC_INLINE_ASM)
  #include <immintrin.h>
#endif

namespace Botan {

RDRAND_RNG::RDRAND_RNG()
   {
   if(!RDRAND_RNG::available())
      throw Invalid_State("Current CPU does not support RDRAND instruction");
   }

//static
bool RDRAND_RNG::available()
   {
   return CPUID::has_rdrand();
   }

//static
uint32_t RDRAND_RNG::rdrand()
   {
   for(;;)
      {
      bool ok = false;
      uint32_t r = rdrand_status(ok);
      if(ok)
         return r;
      }
   }

//static
BOTAN_FUNC_ISA("rdrnd")
uint32_t RDRAND_RNG::rdrand_status(bool& ok)
   {
   ok = false;
   uint32_t r = 0;

   for(size_t i = 0; i != BOTAN_ENTROPY_RDRAND_RETRIES; ++i)
      {
#if defined(BOTAN_USE_GCC_INLINE_ASM)
      int cf = 0;

      // Encoding of rdrand %eax
      asm(".byte 0x0F, 0xC7, 0xF0; adcl $0,%1" :
          "=a" (r), "=r" (cf) : "0" (r), "1" (cf) : "cc");
#else
      int cf = _rdrand32_step(&r);
#endif
      if(1 == cf)
         {
         ok = true;
         break;
         }
      }

   return r;
   }

#if defined(BOTAN_TARGET_ARCH_IS_X86_64)

namespace {

BOTAN_FUNC_ISA("rdrnd")
uint64_t rdrand64()
   {
   for(;;)
      {
      uint64_t r = 0;

#if defined(BOTAN_USE_GCC_INLINE_ASM)
      int cf = 0;

      // Encoding of rdrand %rax
      asm(".byte 0x48, 0x0F, 0xC7, 0xF0; adcl $0,%1" :
          "=a" (r), "=r" (cf) : "0" (r), "1" (cf) : "cc");
#else
      int cf = _rdrand64_step(&r);
#endif
      if(1 == cf)
         {
         return r;
         }
      }

   return 0;
   }

}

#endif

void RDRAND_RNG::randomize(uint8_t out[], size_t out_len)
   {
#if defined(BOTAN_TARGET_ARCH_IS_X86_64)
   while(out_len >= 8)
      {
      const uint64_t r = rdrand64();

      store_le(r, out);
      out += 8;
      out_len -= 8;
      }
#endif

   while(out_len >= 4)
      {
      const uint32_t r = RDRAND_RNG::rdrand();

      store_le(r, out);
      out += 4;
      out_len -= 4;
      }

   if(out_len) // final trailing bytes, at most 3
      {
      const uint32_t r = RDRAND_RNG::rdrand();
      for(size_t i = 0; i != out_len; ++i)
         out[i] = get_byte(i, r);
      }
   }

}
