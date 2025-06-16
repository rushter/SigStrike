use crate::values::ValueType;
use num_enum::TryFromPrimitive;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Clone, Copy, TryFromPrimitive)]
#[repr(u16)]
pub enum SettingsType {
    None = 0,
    Short = 1,
    Int = 2,
    Ptr = 3,
}

#[derive(Debug, TryFromPrimitive, PartialEq, Eq)]
#[repr(u32)]
pub enum TransformStep {
    Append = 1,
    Prepend = 2,
    Base64 = 3,
    Print = 4,
    Parameter = 5,
    Header = 6,
    Build = 7,
    Netbios = 8,
    Parameter_ = 9,
    Header_ = 10,
    NetbiosU = 11,
    UriAppend = 12,
    Base64Url = 13,
    StrRep = 14,
    Mask = 15,
    // CobaltStrike version >= 4.0 (Dec 5, 2019)
    HostHeader_ = 16,
}

impl TransformStep {
    pub fn to_name(&self) -> String {
        match self {
            TransformStep::Append => "APPEND",
            TransformStep::Prepend => "PREPEND",
            TransformStep::Base64 => "BASE64",
            TransformStep::Print => "PRINT",
            TransformStep::Parameter => "PARAMETER",
            TransformStep::Header => "HEADER",
            TransformStep::Build => "BUILD",
            TransformStep::Netbios => "NETBIOS",
            TransformStep::Parameter_ => "_PARAMETER",
            TransformStep::Header_ => "_HEADER",
            TransformStep::NetbiosU => "NETBIOSU",
            TransformStep::UriAppend => "URI_APPEND",
            TransformStep::Base64Url => "BASE64URL",
            TransformStep::StrRep => "STRREP",
            TransformStep::Mask => "MASK",
            TransformStep::HostHeader_ => "_HOSTHEADER",
        }
        .to_string()
    }
}

#[derive(Debug, TryFromPrimitive, Eq, PartialEq, Hash, Serialize)]
#[repr(u16)]
pub enum BeaconSetting {
    #[serde(rename = "SETTING_PROTOCOL")]
    SettingProtocol = 1,

    #[serde(rename = "SETTING_PORT")]
    SettingPort = 2,

    #[serde(rename = "SETTING_SLEEPTIME")]
    SettingSleeptime = 3,

    #[serde(rename = "SETTING_MAXGET")]
    SettingMaxget = 4,

    #[serde(rename = "SETTING_JITTER")]
    SettingJitter = 5,

    #[serde(rename = "SETTING_MAXDNS")]
    SettingMaxdns = 6,

    #[serde(rename = "SETTING_PUBKEY")]
    SettingPubkey = 7,

    #[serde(rename = "SETTING_DOMAINS")]
    SettingDomains = 8,

    #[serde(rename = "SETTING_USERAGENT")]
    SettingUseragent = 9,

    #[serde(rename = "SETTING_SUBMITURI")]
    SettingSubmituri = 10,

    #[serde(rename = "SETTING_C2_RECOVER")]
    SettingC2Recover = 11,

    #[serde(rename = "SETTING_C2_REQUEST")]
    SettingC2Request = 12,

    #[serde(rename = "SETTING_C2_POSTREQ")]
    SettingC2Postreq = 13,

    #[serde(rename = "SETTING_SPAWNTO")]
    SettingSpawnto = 14,

    #[serde(rename = "SETTING_PIPENAME")]
    SettingPipename = 15,

    // Overlap: deprecated & replaced in 4.7
    #[serde(rename = "SETTING_BOF_ALLOCATOR")]
    SettingBofAllocator = 16,

    // Overlap: deprecated & replaced in 4.8
    #[serde(rename = "SETTING_SYSCALL_METHOD")]
    SettingSyscallMethod = 17,

    #[serde(rename = "SETTING_KILLDATE_DAY")]
    SettingKilldateDay = 18,

    #[serde(rename = "SETTING_DNS_IDLE")]
    SettingDnsIdle = 19,

    #[serde(rename = "SETTING_DNS_SLEEP")]
    SettingDnsSleep = 20,

    #[serde(rename = "SETTING_SSH_HOST")]
    SettingSshHost = 21,

    #[serde(rename = "SETTING_SSH_PORT")]
    SettingSshPort = 22,

    #[serde(rename = "SETTING_SSH_USERNAME")]
    SettingSshUsername = 23,

    #[serde(rename = "SETTING_SSH_PASSWORD")]
    SettingSshPassword = 24,

    #[serde(rename = "SETTING_SSH_KEY")]
    SettingSshKey = 25,

    #[serde(rename = "SETTING_C2_VERB_GET")]
    SettingC2VerbGet = 26,

    #[serde(rename = "SETTING_C2_VERB_POST")]
    SettingC2VerbPost = 27,

    #[serde(rename = "SETTING_C2_CHUNK_POST")]
    SettingC2ChunkPost = 28,

    #[serde(rename = "SETTING_SPAWNTO_X86")]
    SettingSpawntoX86 = 29,

    #[serde(rename = "SETTING_SPAWNTO_X64")]
    SettingSpawntoX64 = 30,

    #[serde(rename = "SETTING_CRYPTO_SCHEME")]
    SettingCryptoScheme = 31,

    #[serde(rename = "SETTING_PROXY_CONFIG")]
    SettingProxyConfig = 32,

    #[serde(rename = "SETTING_PROXY_USER")]
    SettingProxyUser = 33,

    #[serde(rename = "SETTING_PROXY_PASSWORD")]
    SettingProxyPassword = 34,

    #[serde(rename = "SETTING_PROXY_BEHAVIOR")]
    SettingProxyBehavior = 35,

    #[serde(rename = "SETTING_WATERMARKHASH")]
    SettingWatermarkhash = 36,

    #[serde(rename = "SETTING_WATERMARK")]
    SettingWatermark = 37,

    #[serde(rename = "SETTING_CLEANUP")]
    SettingCleanup = 38,

    #[serde(rename = "SETTING_CFG_CAUTION")]
    SettingCfgCaution = 39,

    #[serde(rename = "SETTING_KILLDATE")]
    SettingKilldate = 40,

    #[serde(rename = "SETTING_GARGLE_NOOK")]
    SettingGargleNook = 41,

    #[serde(rename = "SETTING_GARGLE_SECTIONS")]
    SettingGargleSections = 42,

    #[serde(rename = "SETTING_PROCINJ_PERMS_I")]
    SettingProcinjPermsI = 43,

    #[serde(rename = "SETTING_PROCINJ_PERMS")]
    SettingProcinjPerms = 44,

    #[serde(rename = "SETTING_PROCINJ_MINALLOC")]
    SettingProcinjMinalloc = 45,

    #[serde(rename = "SETTING_PROCINJ_TRANSFORM_X86")]
    SettingProcinjTransformX86 = 46,

    #[serde(rename = "SETTING_PROCINJ_TRANSFORM_X64")]
    SettingProcinjTransformX64 = 47,

    #[serde(rename = "SETTING_PROCINJ_BOF_REUSE_MEM")]
    SettingProcinjBofReuseMem = 48,

    #[serde(rename = "SETTING_BINDHOST")]
    SettingBindhost = 49,

    #[serde(rename = "SETTING_HTTP_NO_COOKIES")]
    SettingHttpNoCookies = 50,

    #[serde(rename = "SETTING_PROCINJ_EXECUTE")]
    SettingProcinjExecute = 51,

    #[serde(rename = "SETTING_PROCINJ_ALLOCATOR")]
    SettingProcinjAllocator = 52,

    #[serde(rename = "SETTING_PROCINJ_STUB")]
    SettingProcinjStub = 53,

    #[serde(rename = "SETTING_HOST_HEADER")]
    SettingHostHeader = 54,

    #[serde(rename = "SETTING_EXIT_FUNK")]
    SettingExitFunk = 55,

    #[serde(rename = "SETTING_SSH_BANNER")]
    SettingSshBanner = 56,

    #[serde(rename = "SETTING_SMB_FRAME_HEADER")]
    SettingSmbFrameHeader = 57,

    #[serde(rename = "SETTING_TCP_FRAME_HEADER")]
    SettingTcpFrameHeader = 58,

    #[serde(rename = "SETTING_HEADERS_REMOVE")]
    SettingHeadersRemove = 59,

    #[serde(rename = "SETTING_DNS_BEACON_BEACON")]
    SettingDnsBeaconBeacon = 60,

    #[serde(rename = "SETTING_DNS_BEACON_GET_A")]
    SettingDnsBeaconGetA = 61,

    #[serde(rename = "SETTING_DNS_BEACON_GET_AAAA")]
    SettingDnsBeaconGetAaaa = 62,

    #[serde(rename = "SETTING_DNS_BEACON_GET_TXT")]
    SettingDnsBeaconGetTxt = 63,

    #[serde(rename = "SETTING_DNS_BEACON_PUT_METADATA")]
    SettingDnsBeaconPutMetadata = 64,

    #[serde(rename = "SETTING_DNS_BEACON_PUT_OUTPUT")]
    SettingDnsBeaconPutOutput = 65,

    #[serde(rename = "SETTING_DNSRESOLVER")]
    SettingDnsresolver = 66,

    #[serde(rename = "SETTING_DOMAIN_STRATEGY")]
    SettingDomainStrategy = 67,

    #[serde(rename = "SETTING_DOMAIN_STRATEGY_SECONDS")]
    SettingDomainStrategySeconds = 68,

    #[serde(rename = "SETTING_DOMAIN_STRATEGY_FAIL_X")]
    SettingDomainStrategyFailX = 69,

    #[serde(rename = "SETTING_DOMAIN_STRATEGY_FAIL_SECONDS")]
    SettingDomainStrategyFailSeconds = 70,

    #[serde(rename = "SETTING_MAX_RETRY_STRATEGY_ATTEMPTS")]
    SettingMaxRetryStrategyAttempts = 71,

    #[serde(rename = "SETTING_MAX_RETRY_STRATEGY_INCREASE")]
    SettingMaxRetryStrategyIncrease = 72,

    #[serde(rename = "SETTING_MAX_RETRY_STRATEGY_DURATION")]
    SettingMaxRetryStrategyDuration = 73,

    #[serde(rename = "SETTING_MASKED_WATERMARK")]
    SettingMaskedWatermark = 74,

    #[serde(rename = "SETTING_DATA_STORE_SIZE")]
    SettingDataStoreSize = 76,

    #[serde(rename = "SETTING_HTTP_DATA_REQUIRED")]
    SettingHttpDataRequired = 77,

    #[serde(rename = "SETTING_BEACON_GATE")]
    SettingBeaconGate = 78,
}

#[derive(Debug, TryFromPrimitive, PartialEq)]
#[repr(u8)]
pub enum InjectExecutor {
    CreateThread = 1,
    SetThreadContext = 2,
    CreateRemoteThread = 3,
    RtlCreateUserThread = 4,
    NtQueueApcThread = 5,
    CreateThread_ = 6,
    CreateRemoteThread_ = 7,
    NtQueueApcThreadS = 8,
}

impl InjectExecutor {
    pub fn to_name(&self) -> String {
        match self {
            InjectExecutor::CreateThread => "CreateThread",
            InjectExecutor::SetThreadContext => "SetThreadContext",
            InjectExecutor::CreateRemoteThread => "CreateRemoteThread",
            InjectExecutor::RtlCreateUserThread => "RtlCreateUserThread",
            InjectExecutor::NtQueueApcThread => "NtQueueApcThread",
            InjectExecutor::CreateThread_ => "CreateThread_",
            InjectExecutor::CreateRemoteThread_ => "CreateRemoteThread_",
            InjectExecutor::NtQueueApcThreadS => "NtQueueApcThread_s",
        }
        .to_string()
    }
}

#[derive(Debug, TryFromPrimitive, PartialEq)]
#[repr(u16)]
pub enum BofAllocator {
    VirtualAlloc = 0,
    MapViewOfFile = 1,
    HeapAlloc = 2,
}

impl BofAllocator {
    pub fn to_name(&self) -> String {
        match self {
            BofAllocator::VirtualAlloc => "VirtualAlloc",
            BofAllocator::MapViewOfFile => "MapViewOfFile",
            BofAllocator::HeapAlloc => "HeapAlloc",
        }
        .to_string()
    }
}

pub type ParsedBeaconItems = HashMap<BeaconSetting, ValueType>;

#[derive(Debug, Serialize)]
pub struct ParsedBeacon {
    pub items: ParsedBeaconItems,
    pub xor_key: Option<u8>,
    pub encrypted: bool,
    pub guardrailed: bool,
    pub guardrail_key: Option<String>,
    pub input_hash: Option<String>,
}
