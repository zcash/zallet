/**
 * Zallet / Zebrad JSON-RPC 调用示例
 *
 * 对应接口：tensis/chain-adapter/src/controller/chain/zcash.controller.ts
 * 参考实现：tensis/chain-adapter/src/service/zcash/zcash.service.ts
 *
 * 运行方式：
 *   npx tsx example.ts
 *   # 或
 *   ts-node example.ts
 *
 * 前置条件：zebrad（8232）和 zallet（28232）均已启动
 */

// ─── 配置 ────────────────────────────────────────────────────────────────────

const ZEBRAD_URL = "http://127.0.0.1:8232";
const ZALLET_URL = "http://127.0.0.1:28232";

// zallet add-rpc-user 创建的凭据
const ZALLET_USER = "rpcuser";
const ZALLET_PASS = "rpcpassword";
const ZALLET_AUTH =
  "Basic " + Buffer.from(`${ZALLET_USER}:${ZALLET_PASS}`).toString("base64");

// ZIP-317
const ZIP317_MARGINAL_FEE = 5000n;
const ZIP317_GRACE_ACTIONS = 2n;
const ZIP317_MIN_FEE = 10000n;

// z_sendmany 轮询参数
const POLL_INTERVAL_MS = 2000;
const POLL_MAX_ATTEMPTS = 30;

// ─── JSON-RPC helpers ────────────────────────────────────────────────────────

async function jsonRpc(
  url: string,
  method: string,
  params: unknown[],
  auth: string | null,
  timeoutMs = 15000
): Promise<unknown> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (auth) headers["Authorization"] = auth;

  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });
    const json = (await res.json()) as { result?: unknown; error?: unknown };
    if (json.error) {
      throw new Error(`JSON-RPC [${method}] error: ${JSON.stringify(json.error)}`);
    }
    return json.result;
  } finally {
    clearTimeout(timer);
  }
}

/** zebrad（无认证）*/
function zebradRpc(method: string, params: unknown[]): Promise<unknown> {
  return jsonRpc(ZEBRAD_URL, method, params, null, 15000);
}

/** zallet（Basic Auth，可指定超时） */
function zalletRpc(
  method: string,
  params: unknown[],
  timeoutMs = 15000
): Promise<unknown> {
  return jsonRpc(ZALLET_URL, method, params, ZALLET_AUTH, timeoutMs);
}

// ─── 业务函数 ─────────────────────────────────────────────────────────────────

/**
 * 1. 创建账户 — POST /zcash/create/account/hd
 *
 * 流程：getwalletinfo(seedfp) → z_getnewaccount → z_getaddressforaccount
 *       → z_listunifiedreceivers → 提取 p2pkh t1 地址
 *
 * 注：zallet 私钥托管在钱包节点，不向外暴露；mnemonic 通过
 *     `zallet import-mnemonic` 离线导入，createAccount 只负责派生新地址。
 */
async function createAccount(): Promise<{ address: string }> {
  // Step 1: 获取钱包的 mnemonic seed fingerprint
  const walletInfo = (await zalletRpc("getwalletinfo", [])) as Record<
    string,
    string
  >;
  const seedfp = walletInfo?.mnemonic_seedfp;
  if (!seedfp) throw new Error("getwalletinfo 未返回 mnemonic_seedfp");

  // Step 2: 创建新账户，获取 account_uuid
  const accountRes = (await zalletRpc("z_getnewaccount", [seedfp])) as Record<
    string,
    string
  >;
  const accountUuid = accountRes?.account_uuid;
  if (!accountUuid) throw new Error("z_getnewaccount 未返回 account_uuid");

  // Step 3: 生成 Unified Address（zallet alpha 要求至少含一个 shielded receiver）
  // 超时 60s：钱包同步期间生成地址较慢
  const addrRes = (await zalletRpc(
    "z_getaddressforaccount",
    [accountUuid, ["p2pkh", "orchard"]],
    60000
  )) as Record<string, string>;
  const unifiedAddress = addrRes?.address;
  if (!unifiedAddress) throw new Error("z_getaddressforaccount 未返回 address");

  // Step 4: 从 UA 中提取透明 p2pkh t1 地址
  const receivers = (await zalletRpc("z_listunifiedreceivers", [
    unifiedAddress,
  ])) as Record<string, string>;
  const tAddress = receivers?.p2pkh;
  if (!tAddress) throw new Error("z_listunifiedreceivers 未返回 p2pkh receiver");

  return { address: tAddress };
}

/**
 * 2. 查询余额 — POST /zcash/address/token/balance
 *
 * 调用 zebrad getaddressbalance，返回 zatoshi 字符串。
 * 注：zebrad 只统计透明池余额；shielded 余额需调 zallet z_getbalances。
 */
async function addressBalance(address: string): Promise<string> {
  const res = (await zebradRpc("getaddressbalance", [
    { addresses: [address] },
  ])) as Record<string, number>;
  return String(res?.balance ?? 0);
}

/**
 * 3. 验证地址 — POST /zcash/address/validate
 *
 * 仅支持 t1 前缀的透明地址；调 zallet validateaddress 做格式校验。
 */
async function addressValidate(address: string): Promise<boolean> {
  if (!address || !address.startsWith("t1")) return false;
  const res = (await zalletRpc("validateaddress", [address])) as Record<
    string,
    unknown
  >;
  return res?.isvalid === true;
}

/**
 * 4. 最新区块高度 — POST /zcash/last/block
 *
 * 调 zebrad getblockcount，返回高度字符串。
 */
async function lastBlock(): Promise<string> {
  const height = await zebradRpc("getblockcount", []);
  return String(height);
}

/**
 * 5. 按高度扫描钱包交易 — POST /zcash/block/txs
 *
 * 流程：
 *   a. 枚举钱包所有 t-address（z_listaccounts → z_listunifiedreceivers）
 *   b. 查询该高度内涉及钱包地址的 txid（zebrad getaddresstxids）
 *   c. 逐笔解析：提现走 z_viewtransaction；充值解析 vout
 */
async function getTransactionsByHeight(height: number): Promise<{
  block: { height: number; timestamp: number };
  tx: Array<Record<string, unknown>>;
}> {
  // a. 枚举钱包 t-address
  const walletAddresses = await listWalletTAddresses();

  // 同时拉区块 timestamp
  const block = (await zebradRpc("getblock", [String(height), 1])) as Record<
    string,
    unknown
  >;
  const resBlock = { height, timestamp: (block?.time as number) ?? 0 };

  if (walletAddresses.size === 0) {
    return { block: resBlock, tx: [] };
  }

  // b. 查询该高度钱包相关 txid
  const txids = ((await zebradRpc("getaddresstxids", [
    { addresses: [...walletAddresses], start: height, end: height },
  ]).catch(() => [])) as string[]);

  // c. 逐笔解析
  const txList: Array<Record<string, unknown>> = [];

  for (const txid of txids) {
    const rawTx = (await zebradRpc("getrawtransaction", [txid, 1])) as Record<
      string,
      unknown
    >;
    if (!rawTx || !isTransparentTx(rawTx)) continue;

    // 提现：z_viewtransaction 能感知（钱包发起的转账）
    const viewTx = await zalletRpc("z_viewtransaction", [txid]).catch(
      () => null
    );
    if (viewTx) {
      txList.push(
        ...buildTxListFromViewTx(viewTx as Record<string, unknown>, height)
      );
      continue;
    }

    // 充值：解析 vout 中属于钱包的输出
    const vouts = (rawTx.vout as Array<Record<string, unknown>>) ?? [];
    for (const vout of vouts) {
      const scriptPubKey = vout.scriptPubKey as Record<string, unknown>;
      const addr = (scriptPubKey?.addresses as string[])?.[0];
      if (!addr || !walletAddresses.has(addr)) continue;

      txList.push({
        hash: rawTx.txid,
        contract: null,
        sender: "",
        recipient: addr,
        amount: String(
          (vout.valueZat as number) ?? Math.round(((vout.value as number) ?? 0) * 1e8)
        ),
        fee: "0",
        timestamp: (rawTx.blocktime as number) ?? resBlock.timestamp,
        success: true,
        memo: null,
        extra: "deposit",
      });
    }
  }

  return { block: resBlock, tx: txList };
}

/**
 * 6. 发起转账 — POST /zcash/token/transfer/single
 *
 * z_sendmany 异步操作：立即返回 opid，轮询 z_getoperationstatus 直至成功/失败。
 * fee=null 让 zallet 按 ZIP-317 自动计算；privacy_policy 允许显示金额（透明地址必须）。
 */
async function transfer(
  sender: string,
  recipient: string,
  amountZatoshi: string
): Promise<string> {
  const amountZec = Number(BigInt(amountZatoshi)) / 1e8;

  const opid = (await zalletRpc("z_sendmany", [
    sender,
    [{ address: recipient, amount: amountZec }],
    1,    // minconf
    null, // fee=null → ZIP-317 自动计算
    ["AllowRevealedAmounts"],
  ])) as string;

  if (!opid) throw new Error("z_sendmany 未返回 opid");
  console.log(`z_sendmany opid: ${opid}`);

  return pollOperationStatus(opid);
}

/**
 * 7. 手续费预估 — POST /zcash/estimate/fee
 *
 * ZIP-317 本地公式（一对一转账，2 个 logical actions）：
 *   fee = max(ZIP317_MIN_FEE, ZIP317_MARGINAL_FEE × grace_actions)
 *       = max(10000, 5000 × 2) = 10000 zatoshi
 *
 * 多输入/输出场景：fee = 5000 × max(actions, 2)
 */
function estimateFee(actions = 2): string {
  const n = BigInt(actions);
  const fee = ZIP317_MARGINAL_FEE * (n < ZIP317_GRACE_ACTIONS ? ZIP317_GRACE_ACTIONS : n);
  return (fee < ZIP317_MIN_FEE ? ZIP317_MIN_FEE : fee).toString();
}

/**
 * 8. 按 txHash 查询交易 — POST /v2/zcash/transactions
 *
 * 仅处理纯透明交易（含隐私输出的交易返回 null）。
 * 发款方地址通过 vin[0] 反查上一笔交易的 vout 获得。
 */
async function getTransactionsByTxHash(
  txHash: string,
  height = 0
): Promise<{
  block: { height: number; timestamp: number };
  tx: Array<Record<string, unknown>>;
} | null> {
  const rawTx = (await zebradRpc("getrawtransaction", [txHash, 1])) as Record<
    string,
    unknown
  >;
  if (!rawTx) return null;

  if (!isTransparentTx(rawTx)) {
    console.log(`[${txHash}] 含隐私输出，跳过`);
    return null;
  }

  const sender = await resolveSenderAddress(txHash);
  const blockHeight = height > 0 ? height : (rawTx.height as number) ?? 0;
  const resBlock = {
    height: blockHeight,
    timestamp: (rawTx.blocktime as number) ?? (rawTx.time as number) ?? 0,
  };

  const txList: Array<Record<string, unknown>> = [];
  const vouts = (rawTx.vout as Array<Record<string, unknown>>) ?? [];

  for (const vout of vouts) {
    const scriptPubKey = vout.scriptPubKey as Record<string, unknown>;
    const addr = (scriptPubKey?.addresses as string[])?.[0];
    if (!addr) continue;

    txList.push({
      hash: rawTx.txid,
      contract: null,
      sender,
      recipient: addr,
      amount: String(
        (vout.valueZat as number) ?? Math.round(((vout.value as number) ?? 0) * 1e8)
      ),
      fee: "0",
      timestamp: resBlock.timestamp,
      success: true,
      memo: null,
      extra: null,
    });
  }

  return { block: resBlock, tx: txList };
}

// ─── 私有辅助函数 ─────────────────────────────────────────────────────────────

/** 枚举钱包所有透明 t-address */
async function listWalletTAddresses(): Promise<Set<string>> {
  const accounts = ((await zalletRpc("z_listaccounts", [])) ?? []) as Array<
    Record<string, unknown>
  >;

  const uas: string[] = [];
  for (const account of accounts) {
    for (const addr of (account.addresses as Array<Record<string, string>>) ?? []) {
      if (addr.ua) uas.push(addr.ua);
    }
  }

  const results = await Promise.allSettled(
    uas.map((ua) => zalletRpc("z_listunifiedreceivers", [ua]))
  );

  const tAddresses = new Set<string>();
  for (const result of results) {
    if (result.status === "fulfilled") {
      const p2pkh = (result.value as Record<string, string>)?.p2pkh;
      if (p2pkh) tAddresses.add(p2pkh);
    }
  }
  return tAddresses;
}

/** 判断是否为纯透明交易（无任何隐私输出） */
function isTransparentTx(tx: Record<string, unknown>): boolean {
  return (
    ((tx.vShieldedOutput as unknown[])?.length ?? 0) === 0 &&
    ((tx.orchard as Record<string, unknown[]>)?.actions?.length ?? 0) === 0 &&
    ((tx.vjoinsplit as unknown[])?.length ?? 0) === 0
  );
}

/** 通过 vin[0] 反查发款 t-address（coinbase / shielded spend 时返回空字符串） */
async function resolveSenderAddress(txid: string): Promise<string> {
  try {
    const rawTx = (await zebradRpc("getrawtransaction", [txid, 1])) as Record<
      string,
      unknown
    >;
    const vin0 = (rawTx?.vin as Array<Record<string, unknown>>)?.[0];
    if (!vin0?.txid) return "";
    const prevTx = (await zebradRpc("getrawtransaction", [vin0.txid, 1])) as Record<
      string,
      unknown
    >;
    const vouts = prevTx?.vout as Array<Record<string, unknown>>;
    const scriptPubKey = vouts?.[vin0.vout as number]?.scriptPubKey as Record<
      string,
      unknown
    >;
    return (scriptPubKey?.addresses as string[])?.[0] ?? "";
  } catch {
    return "";
  }
}

/** 将 z_viewtransaction 结果解析为 tx 列表 */
function buildTxListFromViewTx(
  tx: Record<string, unknown>,
  height: number
): Array<Record<string, unknown>> {
  const feeZat = tx.fee != null ? Math.round((tx.fee as number) * 1e8) : 0;
  const timestamp = (tx.blocktime as number) ?? 0;
  const isWithdrawal = (tx.outputs as Array<Record<string, unknown>>)?.some(
    (o) => !o.walletInternal && o.outgoing
  );

  const txList: Array<Record<string, unknown>> = [];

  for (const output of (tx.outputs as Array<Record<string, unknown>>) ?? []) {
    if (output.walletInternal) continue; // 跳过找零 / 内部转账

    const recipient = output.address as string;
    if (!recipient) continue;

    txList.push({
      hash: tx.txid,
      contract: null,
      sender: isWithdrawal && output.outgoing ? "(wallet)" : "",
      recipient,
      amount: String(
        (output.valueZat as number) ?? Math.round(((output.value as number) ?? 0) * 1e8)
      ),
      fee: String(feeZat),
      timestamp,
      success: tx.status === "mined",
      memo: (output.memoStr ?? output.memo ?? null) as string | null,
      extra: output.outgoing ? "withdraw" : "deposit",
    });
  }

  return txList;
}

/** 轮询 z_getoperationstatus 直到操作完成，返回 txid */
async function pollOperationStatus(opid: string): Promise<string> {
  for (let i = 0; i < POLL_MAX_ATTEMPTS; i++) {
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));

    const ops = (await zalletRpc("z_getoperationstatus", [[opid]])) as Array<
      Record<string, unknown>
    >;
    if (!ops || ops.length === 0) continue;

    const op = ops[0];
    if (op.status === "success") {
      const txid = (op.result as Record<string, string>)?.txid;
      if (!txid) throw new Error("操作成功但未返回 txid");
      return txid;
    }
    if (op.status === "failed") {
      throw new Error(
        `z_sendmany 失败: ${(op.error as Record<string, string>)?.message ?? "未知错误"}`
      );
    }
  }
  throw new Error(`z_sendmany 超时 (${(POLL_MAX_ATTEMPTS * POLL_INTERVAL_MS) / 1000}s)`);
}

// ─── main ─────────────────────────────────────────────────────────────────────

async function main() {
  // ── 4. 最新区块高度 ──────────────────────────────────────────────────────
  console.log("=== lastBlock ===");
  const height = await lastBlock();
  console.log("height:", height);

  // ── 1. 创建账户 ──────────────────────────────────────────────────────────
  // console.log("\n=== createAccount ===");
  // const account = await createAccount();
  // console.log("account:", account);

  // ── 3. 验证地址 ──────────────────────────────────────────────────────────
  // console.log("\n=== addressValidate ===");
  // const valid = await addressValidate("t1YourAddressHere");
  // console.log("isvalid:", valid);

  // ── 2. 查询余额 ──────────────────────────────────────────────────────────
  // console.log("\n=== addressBalance ===");
  // const balance = await addressBalance("t1YourAddressHere");
  // console.log("balance (zatoshi):", balance);

  // ── 7. 预估手续费 ────────────────────────────────────────────────────────
  console.log("\n=== estimateFee ===");
  console.log("fee (zatoshi):", estimateFee()); // 一对一：10000 zatoshi

  // ── 5. 按高度扫描交易 ────────────────────────────────────────────────────
  // console.log("\n=== getTransactionsByHeight ===");
  // const blockTxs = await getTransactionsByHeight(Number(height));
  // console.log("txs:", JSON.stringify(blockTxs, null, 2));

  // ── 8. 按 txHash 查询 ────────────────────────────────────────────────────
  // console.log("\n=== getTransactionsByTxHash ===");
  // const txDetail = await getTransactionsByTxHash("txHashHere");
  // console.log("tx:", JSON.stringify(txDetail, null, 2));

  // ── 6. 发起转账 ──────────────────────────────────────────────────────────
  // console.log("\n=== transfer ===");
  // const txid = await transfer(
  //   "t1SenderAddress",
  //   "t1RecipientAddress",
  //   "100000"   // 0.001 ZEC in zatoshi
  // );
  // console.log("txid:", txid);
}

main().catch(console.error);
