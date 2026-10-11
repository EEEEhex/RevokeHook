#include "../RevokeHook/add2db_args.h"

#include <array>
#include <cstdio>
#include <cstdlib>

static void Check(bool passed, const char* message)
{
    if (!passed)
    {
        std::fprintf(stderr, "FAILED: %s\n", message);
        std::exit(1);
    }
}

int main()
{
    // Bytes from the verified Weixin 4.1.15.50 call site, including rel32.
    const std::array<std::uint8_t, 18> call = {{
        0xC6, 0x44, 0x24, 0x28, 0x01,
        0xC6, 0x44, 0x24, 0x20, 0x00,
        0x48, 0x89, 0xF2, 0xE8, 0xB3, 0xDE, 0xF2, 0xFF
    }};
    Check(revokehook::MatchesKnownAdd2DbCall(call.data(), call.size()),
        "verified call must match");
    Check(!revokehook::MatchesKnownAdd2DbCall(nullptr, call.size()),
        "null window must be rejected");
    for (std::size_t size = 0; size < call.size(); ++size)
        Check(!revokehook::MatchesKnownAdd2DbCall(call.data(), size),
            "truncated call must be rejected");

    for (std::size_t index = 0; index <= revokehook::kAdd2DbCallPrefixSize; ++index)
    {
        auto different = call;
        different[index] ^= 0x01;
        Check(!revokehook::MatchesKnownAdd2DbCall(different.data(), different.size()),
            "changed setup or opcode must be rejected");
    }
    auto relocated = call;
    for (std::size_t index = 14; index < relocated.size(); ++index)
        relocated[index] ^= 0xFF;
    Check(revokehook::MatchesKnownAdd2DbCall(relocated.data(), relocated.size()),
        "rel32 displacement may vary");

    std::array<std::uint8_t, 64> stack;
    stack.fill(0xA5);
    stack[0x20] = 0; // False byte with nonzero upper bytes, as allowed by the ABI.
    stack[0x28] = 1; // The independent sixth argument must remain unchanged.
    // The seventh and eighth apparent slots are saved RSI and a return address.
    for (std::size_t index = 0x30; index < 0x38; ++index)
        stack[index] = 0;
    const auto before = stack;
    Check(!revokehook::WriteAdd2DbInsertFlag(false, stack.data(), stack.size()),
        "unknown call must not write");
    Check(stack == before, "unknown call changed stack bytes");
    Check(!revokehook::WriteAdd2DbInsertFlag(true, nullptr, stack.size()),
        "null stack must be rejected");
    Check(!revokehook::WriteAdd2DbInsertFlag(true, stack.data(), 0x20),
        "missing flag byte must be rejected");
    Check(stack == before, "rejected write changed stack bytes");
    Check(revokehook::WriteAdd2DbInsertFlag(true, stack.data(), stack.size()),
        "known call must set flag");
    for (std::size_t index = 0; index < stack.size(); ++index)
        Check(stack[index] == (index == 0x20 ? 1 : before[index]),
            "write must affect exactly the fifth argument's low byte");

    std::puts("PASS: call recognition, rejection, and byte-sized stack write");
    return 0;
}
