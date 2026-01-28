/**
 * Stellar/Soroban interaction library for Smart Account operations.
 */

import * as StellarSdk from '@stellar/stellar-sdk'
import { signPadded } from '../falcon'
import {
  RPC_URL,
  NETWORK_PASSPHRASE,
  XLM_SAC_ID,
  FALCON_VERIFIER_ID,
  SMART_ACCOUNT_WASM_HASH,
  DEMO_SECRET,
  getExplorerUrl,
} from './config'

export interface DeployResult {
  success: boolean
  contractId?: string
  transactionHash?: string
  error?: string
  explorerUrl?: string
}

export interface FundResult {
  success: boolean
  amount?: string
  transactionHash?: string
  error?: string
  explorerUrl?: string
}

export interface BalanceResult {
  success: boolean
  balance?: string
  error?: string
}

export interface TransferResult {
  success: boolean
  transactionHash?: string
  explorerUrl?: string
  error?: string
  steps?: TransferStep[]
}

export interface TransferStep {
  name: string
  status: 'pending' | 'running' | 'success' | 'error'
  message?: string
}

export type TransferCallback = (steps: TransferStep[]) => void

/**
 * Get the current ledger sequence
 */
export async function getCurrentLedger(): Promise<number> {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'getLatestLedger',
      params: {},
    }),
  })
  const result = await response.json()
  return result.result?.sequence || 0
}

/**
 * Get account sequence number
 */
export async function getAccountSequence(accountId: string): Promise<string> {
  const server = new StellarSdk.SorobanRpc.Server(RPC_URL)
  const account = await server.getAccount(accountId)
  return account.sequenceNumber()
}

/**
 * Check if we can deploy new contracts
 */
export function canDeployNewContracts(): boolean {
  return SMART_ACCOUNT_WASM_HASH.length === 64
}

/**
 * Deploy a new Falcon Smart Account contract instance.
 */
export async function deploySmartAccount(
  falconPublicKey: Uint8Array
): Promise<DeployResult> {
  if (!SMART_ACCOUNT_WASM_HASH || SMART_ACCOUNT_WASM_HASH.length !== 64) {
    return {
      success: false,
      error: 'WASM hash not configured. Please install the WASM first using:\n' +
        'stellar contract install --wasm <path-to-wasm> --source demo --network testnet\n' +
        'Then set VITE_WASM_HASH in your .env file.',
    }
  }

  try {
    const server = new StellarSdk.SorobanRpc.Server(RPC_URL)
    const sourceKeypair = StellarSdk.Keypair.fromSecret(DEMO_SECRET)
    const sourcePublicKey = sourceKeypair.publicKey()

    const account = await server.getAccount(sourcePublicKey)
    const salt = crypto.getRandomValues(new Uint8Array(32))
    const deployerAddress = StellarSdk.Address.fromString(sourcePublicKey)
    const wasmHashBytes = Buffer.from(SMART_ACCOUNT_WASM_HASH, 'hex')

    const contractIdPreimage = StellarSdk.xdr.ContractIdPreimage.contractIdPreimageFromAddress(
      new StellarSdk.xdr.ContractIdPreimageFromAddress({
        address: deployerAddress.toScAddress(),
        salt: Buffer.from(salt),
      })
    )

    const createContractArgs = new StellarSdk.xdr.CreateContractArgs({
      contractIdPreimage,
      executable: StellarSdk.xdr.ContractExecutable.contractExecutableWasm(
        Buffer.from(wasmHashBytes)
      ),
    })

    const hostFunction = StellarSdk.xdr.HostFunction.hostFunctionTypeCreateContract(createContractArgs)

    const operation = StellarSdk.Operation.invokeHostFunction({
      func: hostFunction,
      auth: [],
    })

    const transaction = new StellarSdk.TransactionBuilder(account, {
      fee: '10000000',
      networkPassphrase: NETWORK_PASSPHRASE,
    })
      .addOperation(operation)
      .setTimeout(300)
      .build()

    const simulation = await server.simulateTransaction(transaction)

    if (StellarSdk.SorobanRpc.Api.isSimulationError(simulation)) {
      return {
        success: false,
        error: `Simulation failed: ${simulation.error}`,
      }
    }

    const preparedTx = StellarSdk.SorobanRpc.assembleTransaction(
      transaction,
      simulation
    ).build()

    preparedTx.sign(sourceKeypair)

    const sendResult = await server.sendTransaction(preparedTx)

    if (sendResult.status === 'ERROR') {
      return {
        success: false,
        error: `Transaction rejected: ${sendResult.errorResult?.result().switch().name || 'Unknown error'}`,
      }
    }

    let txResult = await server.getTransaction(sendResult.hash)
    let attempts = 0
    while (txResult.status === StellarSdk.SorobanRpc.Api.GetTransactionStatus.NOT_FOUND && attempts < 30) {
      await new Promise(resolve => setTimeout(resolve, 1000))
      txResult = await server.getTransaction(sendResult.hash)
      attempts++
    }

    if (txResult.status === StellarSdk.SorobanRpc.Api.GetTransactionStatus.SUCCESS) {
      const contractIdHash = StellarSdk.hash(
        StellarSdk.xdr.HashIdPreimage.envelopeTypeContractId(
          new StellarSdk.xdr.HashIdPreimageContractId({
            networkId: StellarSdk.hash(Buffer.from(NETWORK_PASSPHRASE)),
            contractIdPreimage,
          })
        ).toXDR()
      )

      const contractId = StellarSdk.StrKey.encodeContract(contractIdHash)

      const initResult = await initializeSmartAccount(contractId, falconPublicKey)

      if (!initResult.success) {
        return {
          success: false,
          error: `Contract deployed but initialization failed: ${initResult.error}`,
          contractId,
          transactionHash: sendResult.hash,
        }
      }

      return {
        success: true,
        contractId,
        transactionHash: sendResult.hash,
        explorerUrl: getExplorerUrl(sendResult.hash),
      }
    } else {
      return {
        success: false,
        error: `Transaction failed: ${txResult.status}`,
        transactionHash: sendResult.hash,
      }
    }
  } catch (error) {
    console.error('Deployment error:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
    }
  }
}

/**
 * Initialize a deployed smart account with a Falcon public key.
 */
export async function initializeSmartAccount(
  contractId: string,
  falconPublicKey: Uint8Array
): Promise<DeployResult> {
  try {
    const server = new StellarSdk.SorobanRpc.Server(RPC_URL)
    const sourceKeypair = StellarSdk.Keypair.fromSecret(DEMO_SECRET)
    const sourcePublicKey = sourceKeypair.publicKey()

    const account = await server.getAccount(sourcePublicKey)
    const contract = new StellarSdk.Contract(contractId)

    const pubkeyScVal = StellarSdk.xdr.ScVal.scvBytes(Buffer.from(falconPublicKey))
    const verifierScVal = StellarSdk.Address.fromString(FALCON_VERIFIER_ID).toScVal()

    const operation = contract.call('initialize', pubkeyScVal, verifierScVal)

    const transaction = new StellarSdk.TransactionBuilder(account, {
      fee: '10000000',
      networkPassphrase: NETWORK_PASSPHRASE,
    })
      .addOperation(operation)
      .setTimeout(300)
      .build()

    const simulation = await server.simulateTransaction(transaction)

    if (StellarSdk.SorobanRpc.Api.isSimulationError(simulation)) {
      return {
        success: false,
        error: `Simulation failed: ${simulation.error}`,
      }
    }

    const preparedTx = StellarSdk.SorobanRpc.assembleTransaction(
      transaction,
      simulation
    ).build()

    preparedTx.sign(sourceKeypair)

    const sendResult = await server.sendTransaction(preparedTx)

    if (sendResult.status === 'ERROR') {
      return {
        success: false,
        error: 'Transaction rejected',
      }
    }

    let txResult = await server.getTransaction(sendResult.hash)
    let attempts = 0
    while (txResult.status === StellarSdk.SorobanRpc.Api.GetTransactionStatus.NOT_FOUND && attempts < 30) {
      await new Promise(resolve => setTimeout(resolve, 1000))
      txResult = await server.getTransaction(sendResult.hash)
      attempts++
    }

    if (txResult.status === StellarSdk.SorobanRpc.Api.GetTransactionStatus.SUCCESS) {
      return {
        success: true,
        contractId,
        transactionHash: sendResult.hash,
        explorerUrl: getExplorerUrl(sendResult.hash),
      }
    } else {
      return {
        success: false,
        error: `Transaction failed: ${txResult.status}`,
        transactionHash: sendResult.hash,
      }
    }
  } catch (error) {
    console.error('Initialization error:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
    }
  }
}

/**
 * Fund a smart account with XLM from the demo account.
 */
export async function fundSmartAccount(
  contractId: string,
  amountXLM: number = 10
): Promise<FundResult> {
  try {
    const sourceKeypair = StellarSdk.Keypair.fromSecret(DEMO_SECRET)
    const sourcePublicKey = sourceKeypair.publicKey()

    // Use Horizon API to get account sequence (more stable than Soroban RPC for this)
    const horizonUrl = 'https://horizon-testnet.stellar.org'
    const accountResponse = await fetch(`${horizonUrl}/accounts/${sourcePublicKey}`)
    const accountData = await accountResponse.json()

    if (!accountResponse.ok || !accountData.sequence) {
      return {
        success: false,
        error: 'Account not found',
      }
    }

    const account = new StellarSdk.Account(sourcePublicKey, accountData.sequence)
    const xlmContract = new StellarSdk.Contract(XLM_SAC_ID)

    const amountStroops = BigInt(amountXLM * 10_000_000)

    const fromScVal = StellarSdk.Address.fromString(sourcePublicKey).toScVal()
    const toScVal = StellarSdk.Address.fromString(contractId).toScVal()
    const amountScVal = StellarSdk.nativeToScVal(amountStroops, { type: 'i128' })

    const operation = xlmContract.call('transfer', fromScVal, toScVal, amountScVal)

    const transaction = new StellarSdk.TransactionBuilder(account, {
      fee: '10000000',
      networkPassphrase: NETWORK_PASSPHRASE,
    })
      .addOperation(operation)
      .setTimeout(300)
      .build()

    // Use raw fetch for simulation to avoid XDR parsing issues
    const simResponse = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'simulateTransaction',
        params: { transaction: transaction.toXDR() },
      }),
    })
    const simResult = await simResponse.json()

    if (simResult.error || simResult.result?.error) {
      return {
        success: false,
        error: `Simulation failed: ${simResult.error?.message || simResult.result?.error}`,
      }
    }

    // Build soroban data from simulation result
    const sorobanData = StellarSdk.xdr.SorobanTransactionData.fromXDR(
      simResult.result.transactionData,
      'base64'
    )
    const minResourceFee = parseInt(simResult.result.minResourceFee || '0')

    // Parse auth entries from simulation
    const authEntries: StellarSdk.xdr.SorobanAuthorizationEntry[] = []
    if (simResult.result.results?.[0]?.auth) {
      for (const authXdr of simResult.result.results[0].auth) {
        authEntries.push(StellarSdk.xdr.SorobanAuthorizationEntry.fromXDR(authXdr, 'base64'))
      }
    }

    // Rebuild operation with auth entries
    const opWithAuth = StellarSdk.Operation.invokeHostFunction({
      func: (transaction.operations[0] as any).func,
      auth: authEntries,
    })

    // Create fresh account with original sequence (account object was mutated by first build)
    const freshAccount = new StellarSdk.Account(sourcePublicKey, accountData.sequence)

    // Build new transaction with auth
    const preparedTx = new StellarSdk.TransactionBuilder(freshAccount, {
      fee: (parseInt(transaction.fee) + minResourceFee).toString(),
      networkPassphrase: NETWORK_PASSPHRASE,
    })
      .addOperation(opWithAuth)
      .setTimeout(300)
      .setSorobanData(sorobanData)
      .build()

    preparedTx.sign(sourceKeypair)

    // Use raw fetch for sending to avoid XDR parsing issues
    const sendResponse = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'sendTransaction',
        params: { transaction: preparedTx.toXDR() },
      }),
    })
    const sendResult = await sendResponse.json()

    console.log('Send result:', sendResult)
    if (sendResult.result?.status === 'ERROR' || sendResult.error) {
      const errorDetail = sendResult.result?.errorResultXdr
        ? (() => {
            try {
              const err = StellarSdk.xdr.TransactionResult.fromXDR(sendResult.result.errorResultXdr, 'base64')
              return err.result().switch().name
            } catch { return 'unknown' }
          })()
        : sendResult.error?.message || 'unknown'
      console.log('Send error detail:', errorDetail, sendResult)
      return {
        success: false,
        error: `Transaction rejected: ${errorDetail}`,
      }
    }

    const txHash = sendResult.result?.hash
    if (!txHash) {
      return {
        success: false,
        error: 'No transaction hash returned',
      }
    }

    let txStatus = 'NOT_FOUND'
    let txResultData: any = null
    let attempts = 0
    while (txStatus === 'NOT_FOUND' && attempts < 30) {
      await new Promise(resolve => setTimeout(resolve, 1000))
      attempts++

      try {
        const statusResponse = await fetch(RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'getTransaction',
            params: { hash: txHash },
          }),
        })
        const statusResult = await statusResponse.json()
        txStatus = statusResult.result?.status || 'NOT_FOUND'
        txResultData = statusResult.result
      } catch (e) {
        console.log('Error checking transaction status:', e)
      }
    }

    if (txStatus === 'SUCCESS') {
      return {
        success: true,
        amount: `${amountXLM} XLM`,
        transactionHash: txHash,
        explorerUrl: getExplorerUrl(txHash),
      }
    } else {
      // Log detailed error info
      console.log('Transaction failed details:', txResultData)
      let errorDetail = txStatus
      if (txResultData?.resultXdr) {
        try {
          const resultXdr = StellarSdk.xdr.TransactionResult.fromXDR(txResultData.resultXdr, 'base64')
          errorDetail = resultXdr.result().switch().name
        } catch (e) {
          console.log('Could not parse result XDR:', e)
        }
      }
      return {
        success: false,
        error: `Transaction failed: ${errorDetail}`,
        transactionHash: txHash,
        explorerUrl: getExplorerUrl(txHash),
      }
    }
  } catch (error) {
    console.error('Funding error:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
    }
  }
}

/**
 * Get the XLM balance of a smart account.
 */
export async function getSmartAccountBalance(contractId: string): Promise<BalanceResult> {
  try {
    const server = new StellarSdk.SorobanRpc.Server(RPC_URL)
    const sourceKeypair = StellarSdk.Keypair.fromSecret(DEMO_SECRET)
    const sourcePublicKey = sourceKeypair.publicKey()

    const account = await server.getAccount(sourcePublicKey)
    const xlmContract = new StellarSdk.Contract(XLM_SAC_ID)

    const addressScVal = StellarSdk.Address.fromString(contractId).toScVal()

    const operation = xlmContract.call('balance', addressScVal)

    const transaction = new StellarSdk.TransactionBuilder(account, {
      fee: '100000',
      networkPassphrase: NETWORK_PASSPHRASE,
    })
      .addOperation(operation)
      .setTimeout(30)
      .build()

    const simulation = await server.simulateTransaction(transaction)

    if (StellarSdk.SorobanRpc.Api.isSimulationError(simulation)) {
      return {
        success: false,
        error: `Simulation failed: ${simulation.error}`,
      }
    }

    if (simulation.result) {
      try {
        const balance = StellarSdk.scValToNative(simulation.result.retval)
        const xlmBalance = Number(balance) / 10_000_000
        return {
          success: true,
          balance: xlmBalance.toFixed(7),
        }
      } catch {
        return {
          success: true,
          balance: '0',
        }
      }
    }

    return {
      success: true,
      balance: '0',
    }
  } catch (error) {
    console.error('Balance error:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
    }
  }
}

/**
 * Transfer XLM from a Falcon Smart Account to a recipient.
 */
export async function transferFromSmartAccount(
  smartAccountId: string,
  recipientAddress: string,
  amountXLM: number,
  falconSeed: Uint8Array,
  onProgress?: TransferCallback
): Promise<TransferResult> {
  const steps: TransferStep[] = [
    { name: 'Build Transaction', status: 'pending' },
    { name: 'Simulate', status: 'pending' },
    { name: 'Sign with Falcon', status: 'pending' },
    { name: 'Re-simulate', status: 'pending' },
    { name: 'Submit', status: 'pending' },
  ]

  const updateStep = (index: number, status: TransferStep['status'], message?: string) => {
    steps[index] = { ...steps[index], status, message }
    onProgress?.(steps)
  }

  try {
    const server = new StellarSdk.SorobanRpc.Server(RPC_URL)
    const feePayerKeypair = StellarSdk.Keypair.fromSecret(DEMO_SECRET)
    const feePayerPublicKey = feePayerKeypair.publicKey()

    // Step 1: Build the transfer transaction
    updateStep(0, 'running')

    const account = await server.getAccount(feePayerPublicKey)
    const xlmContract = new StellarSdk.Contract(XLM_SAC_ID)

    const amountStroops = BigInt(Math.floor(amountXLM * 10_000_000))

    const fromScVal = StellarSdk.Address.fromString(smartAccountId).toScVal()
    const toScVal = StellarSdk.Address.fromString(recipientAddress).toScVal()
    const amountScVal = StellarSdk.nativeToScVal(amountStroops, { type: 'i128' })

    const operation = xlmContract.call('transfer', fromScVal, toScVal, amountScVal)

    const transaction = new StellarSdk.TransactionBuilder(account, {
      fee: '100000',
      networkPassphrase: NETWORK_PASSPHRASE,
    })
      .addOperation(operation)
      .setTimeout(300)
      .build()

    updateStep(0, 'success')

    // Step 2: Simulate to get nonce and invocation
    updateStep(1, 'running')

    const simulation = await server.simulateTransaction(transaction)

    if (StellarSdk.SorobanRpc.Api.isSimulationError(simulation)) {
      updateStep(1, 'error', simulation.error)
      return {
        success: false,
        error: `Simulation failed: ${simulation.error}`,
        steps,
      }
    }

    const authEntries = simulation.result?.auth
    if (!authEntries || authEntries.length === 0) {
      updateStep(1, 'error', 'No auth entries')
      return {
        success: false,
        error: 'No authorization entries in simulation result',
        steps,
      }
    }

    const authEntry = authEntries[0]
    const credentials = authEntry.credentials()

    if (credentials.switch().name !== 'sorobanCredentialsAddress') {
      updateStep(1, 'error', 'Wrong credential type')
      return {
        success: false,
        error: 'Expected address credentials',
        steps,
      }
    }

    const addrCreds = credentials.address()
    const nonce = addrCreds.nonce()
    const invocation = authEntry.rootInvocation()

    const ledgerResponse = await fetch(RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getLatestLedger',
        params: {},
      }),
    })
    const ledgerResult = await ledgerResponse.json()
    const currentLedger = ledgerResult.result?.sequence || 0
    const expirationLedger = currentLedger + 100

    updateStep(1, 'success', `Nonce: ${nonce.toString()}`)

    // Step 3: Sign with Falcon
    updateStep(2, 'running')

    const networkId = StellarSdk.hash(Buffer.from(NETWORK_PASSPHRASE))

    const preimage = StellarSdk.xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
      new StellarSdk.xdr.HashIdPreimageSorobanAuthorization({
        networkId,
        nonce,
        signatureExpirationLedger: expirationLedger,
        invocation,
      })
    )

    const preimageXdr = preimage.toXDR()
    const payloadHash = StellarSdk.hash(preimageXdr)

    console.log('Preimage XDR length:', preimageXdr.length)
    console.log('Payload hash:', Buffer.from(payloadHash).toString('hex'))

    const { signature: falconSignature } = await signPadded(
      new Uint8Array(0),
      new Uint8Array(payloadHash),
      falconSeed
    )

    console.log('Falcon signature length:', falconSignature.length)
    console.log('Falcon signature first 32 bytes:', Buffer.from(falconSignature.slice(0, 32)).toString('hex'))

    updateStep(2, 'success', `Signature: ${falconSignature.length} bytes`)

    // Step 4: Re-simulate with signed auth
    updateStep(3, 'running')

    const sigScVal = StellarSdk.xdr.ScVal.scvBytes(Buffer.from(falconSignature))

    const signedCreds = StellarSdk.xdr.SorobanCredentials.sorobanCredentialsAddress(
      new StellarSdk.xdr.SorobanAddressCredentials({
        address: StellarSdk.Address.fromString(smartAccountId).toScAddress(),
        nonce,
        signatureExpirationLedger: expirationLedger,
        signature: sigScVal,
      })
    )

    const signedAuthEntry = new StellarSdk.xdr.SorobanAuthorizationEntry({
      credentials: signedCreds,
      rootInvocation: invocation,
    })

    const signedOp = StellarSdk.Operation.invokeHostFunction({
      func: StellarSdk.xdr.HostFunction.hostFunctionTypeInvokeContract(
        new StellarSdk.xdr.InvokeContractArgs({
          contractAddress: StellarSdk.Address.fromString(XLM_SAC_ID).toScAddress(),
          functionName: 'transfer',
          args: [fromScVal, toScVal, amountScVal].map(v =>
            typeof v === 'string' ? StellarSdk.xdr.ScVal.fromXDR(v, 'base64') : v
          ),
        })
      ),
      auth: [signedAuthEntry],
    })

    const freshAccount = await server.getAccount(feePayerPublicKey)

    const signedTx = new StellarSdk.TransactionBuilder(freshAccount, {
      fee: '100000',
      networkPassphrase: NETWORK_PASSPHRASE,
    })
      .addOperation(signedOp)
      .setTimeout(300)
      .build()

    let minResourceFee = parseInt(simulation.minResourceFee || '0')
    let txDataB64 = ''

    try {
      const reSimResponse = await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'simulateTransaction',
          params: { transaction: signedTx.toXDR() },
        }),
      })
      const reSimResult = await reSimResponse.json()

      if (reSimResult.result?.error) {
        updateStep(3, 'error', reSimResult.result.error)
        return {
          success: false,
          error: `Re-simulation failed: ${reSimResult.result.error}`,
          steps,
        }
      }

      minResourceFee = parseInt(reSimResult.result?.minResourceFee || simulation.minResourceFee || '0')
      txDataB64 = reSimResult.result?.transactionData || ''
      console.log('Re-simulation fee:', minResourceFee)
    } catch (e) {
      console.log('Re-simulation parsing failed, using first simulation data:', e)
    }

    updateStep(3, 'success', `Fee: ${minResourceFee}`)

    // Step 5: Build final transaction and submit
    updateStep(4, 'running')

    let sorobanData: StellarSdk.xdr.SorobanTransactionData
    if (txDataB64) {
      sorobanData = StellarSdk.xdr.SorobanTransactionData.fromXDR(txDataB64, 'base64')
    } else {
      sorobanData = simulation.transactionData!.build()
    }

    const finalAccount = await server.getAccount(feePayerPublicKey)

    const finalTx = new StellarSdk.TransactionBuilder(finalAccount, {
      fee: (100000 + minResourceFee).toString(),
      networkPassphrase: NETWORK_PASSPHRASE,
    })
      .addOperation(signedOp)
      .setTimeout(300)
      .setSorobanData(sorobanData)
      .build()

    finalTx.sign(feePayerKeypair)

    console.log('Submitting transaction...')

    const sendResult = await server.sendTransaction(finalTx)

    console.log('Send result:', sendResult.status)

    if (sendResult.status === 'ERROR') {
      updateStep(4, 'error', 'Transaction rejected')
      let errorDetail = 'Unknown'
      try {
        if (sendResult.errorResult) {
          errorDetail = sendResult.errorResult.result().switch().name
        }
      } catch (e) {
        console.error('Error parsing error result:', e)
        errorDetail = sendResult.status
      }
      return {
        success: false,
        error: `Transaction rejected: ${errorDetail}`,
        steps,
      }
    }

    console.log('Waiting for confirmation, hash:', sendResult.hash)
    let txStatus = 'NOT_FOUND'
    let attempts = 0

    while (txStatus === 'NOT_FOUND' && attempts < 30) {
      await new Promise(resolve => setTimeout(resolve, 1000))
      attempts++

      try {
        const statusResponse = await fetch(RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'getTransaction',
            params: { hash: sendResult.hash },
          }),
        })
        const statusResult = await statusResponse.json()
        txStatus = statusResult.result?.status || 'NOT_FOUND'
        console.log('Attempt', attempts, 'status:', txStatus)
      } catch (e) {
        console.log('Error checking status:', e)
      }
    }

    if (txStatus === 'SUCCESS') {
      updateStep(4, 'success', 'Transfer complete!')
      return {
        success: true,
        transactionHash: sendResult.hash,
        explorerUrl: getExplorerUrl(sendResult.hash),
        steps,
      }
    } else {
      updateStep(4, 'error', txStatus)
      return {
        success: false,
        error: `Transaction failed: ${txStatus}`,
        transactionHash: sendResult.hash,
        steps,
      }
    }
  } catch (error) {
    console.error('Transfer error:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      steps,
    }
  }
}
