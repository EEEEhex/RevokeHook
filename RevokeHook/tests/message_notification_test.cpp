#include "../RevokeHook/message_notification.h"

#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

using namespace revokehook;

static void Check(bool passed, const char* message)
{
    if (!passed)
    {
        std::fprintf(stderr, "FAILED: %s\n", message);
        std::exit(1);
    }
}

static NotificationProfileView VerifiedProfile()
{
    return {
        0x6AB4F57F, 0x0C31C000, 0x023BAB8A, 0x039B4FD8,
        { kNotifyDeleteBytes, sizeof(kNotifyDeleteBytes) },
        { kNotifyAddBytes, sizeof(kNotifyAddBytes) },
        { kNotifyPostBytes, sizeof(kNotifyPostBytes) },
        { kNotifySignalBytes, sizeof(kNotifySignalBytes) },
        { kNotifyWorkerBytes, sizeof(kNotifyWorkerBytes) }
    };
}

static void TestProfile()
{
    const auto profile = VerifiedProfile();
    Check(MatchesNotificationProfile(profile), "verified profile must match");
    auto changed = profile;
    changed.timestamp ^= 1;
    Check(!MatchesNotificationProfile(changed), "different image timestamp accepted");
    changed = profile;
    changed.image_size ^= 1;
    Check(!MatchesNotificationProfile(changed), "different image size accepted");
    changed = profile;
    changed.delete_call_rva += 1;
    Check(!MatchesNotificationProfile(changed), "different delete call accepted");
    changed = profile;
    changed.add_call_rva += 1;
    Check(!MatchesNotificationProfile(changed), "different add call accepted");

    NotificationBytes NotificationProfileView::* fields[] = {
        &NotificationProfileView::delete_call, &NotificationProfileView::add_call,
        &NotificationProfileView::post_call, &NotificationProfileView::signal_entry,
        &NotificationProfileView::worker_result
    };
    for (auto field : fields)
    {
        const auto original = profile.*field;
        for (std::size_t length = 0; length < original.size; ++length)
        {
            changed = profile;
            (changed.*field).size = length;
            Check(!MatchesNotificationProfile(changed), "truncated profile accepted");
        }
        changed = profile;
        (changed.*field).data = nullptr;
        Check(!MatchesNotificationProfile(changed), "null profile bytes accepted");
        std::vector<std::uint8_t> bytes(original.data, original.data + original.size);
        for (std::size_t index = 0; index < bytes.size(); ++index)
        {
            bytes[index] ^= 1;
            changed = profile;
            changed.*field = { bytes.data(), bytes.size() };
            Check(!MatchesNotificationProfile(changed), "changed profile instruction accepted");
            bytes[index] ^= 1;
        }
    }
}

static void Capture(PendingNotificationTable& table, std::uintptr_t rbp,
    std::uintptr_t rsp, std::uint64_t now = 100)
{
    Check(CapturePendingNotification(table, 0x100000, rbp, rsp, now) ==
        CaptureNotificationResult::Captured, "capture failed");
}

static PendingNotification Find(PendingNotificationTable& table,
    std::uintptr_t rbp, std::uint64_t now = 101)
{
    PendingNotification result = {};
    Check(FindPendingNotification(table, rbp + kNotifyFrameMessageOffset, now, result),
        "pending message not found");
    return result;
}

static void TokenFor(const PendingNotification& record, std::uint8_t (&token)[8])
{
    std::memcpy(token, &record.generation, sizeof(token));
    token[7] = 0x5A;
}

static bool Arm(PendingNotificationTable& table, const PendingNotification& record,
    std::uint32_t old_id, std::uint64_t now)
{
    std::uint8_t token[8] = {};
    TokenFor(record, token);
    return ArmPendingNotification(table, record, old_id, kNotifySrvIdOffset, token, now);
}

static void TestInterleavedFrames()
{
    PendingNotificationTable table = {};
    NotificationRequest request = {};
    Capture(table, 0x200000, 0x1FF000);
    auto first = Find(table, 0x200000);
    Capture(table, 0x300000, 0x2FF000);
    auto second = Find(table, 0x300000);
    Check(Arm(table, first, 10, 102), "first frame was overwritten");
    Check(Arm(table, second, 20, 102), "second frame failed to arm");
    Check(!TakePendingNotification(table, 0x200000, 0x2FF000, 103, request),
        "mixed frame was accepted");
    Check(TakePendingNotification(table, 0x300000, 0x2FF000, 103, request),
        "second frame was consumed by mismatching post");
    Check(request.previous_local_id == 20, "wrong frame data returned");
    Check(TakePendingNotification(table, 0x200000, 0x1FF000, 103, request),
        "first frame was lost");
    Check(request.previous_local_id == 10, "wrong original ID");
    Check(!TakePendingNotification(table, 0x200000, 0x1FF000, 103, request),
        "a second notification was allowed");

    Capture(table, 0x200000, 0x1FF000, 104);
    first = Find(table, 0x200000, 105);
    Check(!TakePendingNotification(table, 0x200000, 0x1FF000, 106, request),
        "unarmed message was accepted");
    Check(!Arm(table, first, 10, 106), "consumed record was rearmed");

    Capture(table, 0x200000, 0x1FF000, 107);
    first = Find(table, 0x200000, 108);
    Capture(table, 0x200000, 0x1FF000, 109);
    Check(!Arm(table, first, 10, 110), "stale generation was accepted");
    first = Find(table, 0x200000, 110);
    Check(!first.armed, "new capture inherited an armed state");
    Check(CapturePendingNotification(table, 0x100000, 0x200000, 0x1EE000, 110) ==
        CaptureNotificationResult::Invalid, "ambiguous message pointer was accepted");
    Check(Arm(table, first, 10, 111), "valid record lost after ambiguity");
    Check(!Arm(table, first, 99, 112), "second arm replaced original ID");
    ClearNotificationFrame(table, 0x300000, 0x2FF000);
    Check(TakePendingNotification(table, 0x200000, 0x1FF000, 112, request),
        "clearing another frame removed valid record");
    Check(request.previous_local_id == 10, "original ID was overwritten");
}

static void TestCrossThreadAndCapacity()
{
    PendingNotificationTable table = {};
    Capture(table, 0x200000, 0x1FF000);
    // Serialized thread handoff: synchronization for concurrent access belongs to the DLL.
    std::thread worker([&table]() {
        const auto record = Find(table, 0x200000);
        Check(Arm(table, record, 10, 102), "cross-thread arm failed");
    });
    worker.join();
    NotificationRequest request = {};
    Check(TakePendingNotification(table, 0x200000, 0x1FF000, 103, request),
        "cross-thread record could not be consumed");
    for (std::size_t index = 0; index < kPendingNotificationCapacity; ++index)
        Capture(table, 0x10000 + index * 0x2000, 0xF000 + index * 0x2000, 200);
    Check(CapturePendingNotification(table, 0x100000, 0x900000, 0x8FF000, 201) ==
        CaptureNotificationResult::Full, "full table did not reject capture");
    for (std::size_t index = 0; index < kPendingNotificationCapacity; ++index)
        Find(table, 0x10000 + index * 0x2000, 201);
    Capture(table, 0x900000, 0x8FF000, 200 + kPendingNotificationTtlMs);
    PendingNotification expired = {};
    Check(!FindPendingNotification(table, 0x10000 + kNotifyFrameMessageOffset,
        200 + kPendingNotificationTtlMs, expired), "expired frame survived");
    Check(CapturePendingNotification(table, 0, 0x800000, 0x7FF000, 30201) ==
        CaptureNotificationResult::Invalid, "null manager accepted");
    Check(CapturePendingNotification(table, 0x100000,
        (std::numeric_limits<std::uintptr_t>::max)() - 8, 0x7FF000, 30201) ==
        CaptureNotificationResult::Invalid, "overflowing frame accepted");
}

static void TestMessageValidation()
{
    NotificationRequest request = {};
    request.manager = 0x100000;
    request.message = 0x200000;
    request.previous_local_id = 10;
    request.committed_local_id = 11;
    request.commit_observed = request.commit_success = true;
    request.random_srvid[0] = 0x91;
    const auto* token = request.random_srvid;
    Check(IsStoredRevokeNotification(request, 11, 10000, true, token), "valid message rejected");
    Check(!IsStoredRevokeNotification(request, 0, 10000, true, token), "zero ID accepted");
    Check(!IsStoredRevokeNotification(request, 10, 10000, true, token), "unchanged ID accepted");
    Check(!IsStoredRevokeNotification(request, 12, 10000, true, token), "different worker ID accepted");
    Check(!IsStoredRevokeNotification(request, 11, 1, true, token), "ordinary message accepted");
    Check(!IsStoredRevokeNotification(request, 11, 10000, false, token), "missing XML accepted");
    std::uint8_t different_token[8] = {};
    Check(!IsStoredRevokeNotification(request, 11, 10000, true, different_token),
        "different post-insert token accepted");
    Check(!IsStoredRevokeNotification(request, 11, 10000, true, nullptr), "missing token accepted");
    Check(MatchesNotificationManager(request, 0x100000), "current manager reference rejected");
    Check(!MatchesNotificationManager(request, 0), "null manager reference accepted");
    Check(!MatchesNotificationManager(request, 0x300000), "different manager reference accepted");

    const char xml[] = "<sysmsg type=\"revokemsg\"><revokemsg><replacemsg>above msg</replacemsg></revokemsg></sysmsg>";
    Check(ContainsRevokeXml(xml, sizeof(xml) - 1), "revoke XML not recognized");
    Check(!ContainsRevokeXml(xml, 12), "truncated XML marker recognized");
    Check(!ContainsRevokeXml("ordinary recalled text", 22), "plain message text accepted as XML");
    Check(!ContainsRevokeXml(nullptr, 20), "null XML accepted");

    MessageVectorView view = {};
    Check(BuildMessageVectorView(0x200000, view), "vector view creation failed");
    Check(reinterpret_cast<std::uintptr_t>(view.begin) == 0x200000 &&
        reinterpret_cast<std::uintptr_t>(view.end) == 0x200000 + 0x2E8 &&
        view.capacity == view.end, "incorrect one-message vector range");
    Check(!BuildMessageVectorView(0, view), "null vector range accepted");
    Check(!BuildMessageVectorView((std::numeric_limits<std::uintptr_t>::max)() - 0x100, view),
        "overflowing vector range accepted");
}

static void TestCommitValidation()
{
    PendingNotificationTable table = {};
    NotificationRequest request = {};
    std::uint8_t token[8] = {};
    Capture(table, 0x200000, 0x1FF000);
    auto record = Find(table, 0x200000);
    TokenFor(record, token);
    Check(!ArmPendingNotification(table, record, 10, 0x150, token, 102),
        "unverified server ID offset accepted");
    Check(Arm(table, record, 10, 102), "arm failed");
    Check(TakePendingNotification(table, 0x200000, 0x1FF000, 103, request), "take failed");
    Check(!IsStoredRevokeNotification(request, 11, 10000, true, token),
        "changed ID without observed transaction result accepted");

    Capture(table, 0x200000, 0x1FF000, 104);
    record = Find(table, 0x200000, 105);
    TokenFor(record, token);
    Check(Arm(table, record, 10, 105), "arm failed");
    Check(RecordNotificationCommit(table, token, false, 11, 106) ==
        CommitNotificationResult::Recorded, "failure result not recorded");
    Check(RecordNotificationCommit(table, token, true, 11, 107) ==
        CommitNotificationResult::Recorded, "later result not recorded");
    Check(TakePendingNotification(table, 0x200000, 0x1FF000, 108, request), "take failed");
    Check(!IsStoredRevokeNotification(request, 11, 10000, true, token),
        "transaction failure with a changed ID was accepted");

    Capture(table, 0x200000, 0x1FF000, 109);
    record = Find(table, 0x200000, 110);
    TokenFor(record, token);
    Check(Arm(table, record, 10, 110), "arm failed");
    std::uint8_t unknown_token[8] = {};
    Check(RecordNotificationCommit(table, unknown_token, true, 11, 111) ==
        CommitNotificationResult::NoMatch, "unrelated worker result matched");
    Check(RecordNotificationCommit(table, token, true, 11, 111) ==
        CommitNotificationResult::Recorded, "success result not recorded");
    Check(TakePendingNotification(table, 0x200000, 0x1FF000, 112, request), "take failed");
    Check(IsStoredRevokeNotification(request, 11, 10000, true, token), "committed message rejected");
    Check(!TakePendingNotification(table, 0x200000, 0x1FF000, 112, request),
        "committed message emitted twice");

    Capture(table, 0x200000, 0x1FF000, 113);
    record = Find(table, 0x200000, 114);
    TokenFor(record, token);
    Check(ArmPendingNotification(table, record, 10, kNotifySrvIdOffset, token, 114), "arm failed");
    Check(RecordNotificationCommit(table, token, true, 11, 114) ==
        CommitNotificationResult::Recorded, "first token result failed");
    Capture(table, 0x300000, 0x2FF000, 115);
    auto other = Find(table, 0x300000, 115);
    Check(ArmPendingNotification(table, other, 20, kNotifySrvIdOffset, token, 115), "arm failed");
    Check(RecordNotificationCommit(table, token, true, 21, 116) ==
        CommitNotificationResult::Ambiguous, "duplicate token was accepted");
    Check(TakePendingNotification(table, 0x200000, 0x1FF000, 117, request), "take failed");
    Check(!IsStoredRevokeNotification(request, 11, 10000, true, token),
        "token ambiguity left an earlier success authorized");
    Check(TakePendingNotification(table, 0x300000, 0x2FF000, 117, request), "take failed");
    Check(!IsStoredRevokeNotification(request, 21, 10000, true, token),
        "ambiguous second message authorized");
}

int main()
{
    TestProfile();
    TestInterleavedFrames();
    TestCrossThreadAndCapacity();
    TestMessageValidation();
    TestCommitValidation();
    std::puts("PASS: strict profile, interleaved frames, thread handoff, capacity/TTL, commit result/token/manager checks, and message view");
    return 0;
}
