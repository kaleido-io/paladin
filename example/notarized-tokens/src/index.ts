import https from "https";
import PaladinClient, {
  NotoFactory,
} from "@lfdecentralizedtrust-labs/paladin-sdk";

const logger = console;

// Initialize Paladin clients for three nodes
//central bank
const centralBank = new PaladinClient({ 
  url: "https://central-bank.kaleido.dev/endpoint/cbdc-sandbox/central-bank/jsonrpc",
  requestConfig: {
    headers: {
      // 4e5e8d2c-19fd-46e6-9efa-cd775201099404a0881d-8119-4de7-8c32-de746efe2554
      Authorization: "Basic a2V5MTo0ZTVlOGQyYy0xOWZkLTQ2ZTYtOWVmYS1jZDc3NTIwMTA5OTQwNGEwODgxZC04MTE5LTRkZTctOGMzMi1kZTc0NmVmZTI1NTQ="
    },
    httpsAgent: new https.Agent({ rejectUnauthorized: false })
  },
 });
const bank1 = new PaladinClient({ 
  url: "https://bank1.kaleido.dev/endpoint/cbdc-sandbox/bank1/jsonrpc",
  requestConfig: {
    headers: {
      // 2e565af1-d542-4e70-94f4-ba04317cc9542024e096-3d3e-4549-a527-28aec043873c
      Authorization: "Basic a2V5MToyZTU2NWFmMS1kNTQyLTRlNzAtOTRmNC1iYTA0MzE3Y2M5NTQyMDI0ZTA5Ni0zZDNlLTQ1NDktYTUyNy0yOGFlYzA0Mzg3M2M="
    },
    httpsAgent: new https.Agent({ rejectUnauthorized: false })
  },
 });
const bank2 = new PaladinClient({ 
  url: "https://bank2.kaleido.dev/endpoint/cbdc-sandbox/bank2/jsonrpc",
  requestConfig: {
    headers: {
      // 78047006-a2d0-42ad-a6a6-3d126dab644d846d5873-2fa2-4ee5-b6a4-ab860e20ed12
      Authorization: "Basic a2V5MTo3ODA0NzAwNi1hMmQwLTQyYWQtYTZhNi0zZDEyNmRhYjY0NGQ4NDZkNTg3My0yZmEyLTRlZTUtYjZhNC1hYjg2MGUyMGVkMTI="
    },
    httpsAgent: new https.Agent({ rejectUnauthorized: false })
  },
 });

async function main(): Promise<boolean> {
  // Retrieve verifiers for each node
  const [verifierCentralBank] = centralBank.getVerifiers("user@central-bank");
  const [verifierBank1] = bank1.getVerifiers("user@bank1");
  const [verifierBank2] = bank2.getVerifiers("user@bank2");

  // Step 1: Deploy a Noto token to represent cash
  logger.log("Step 1: Deploying a Noto cash token...");
  const notoFactory = new NotoFactory(centralBank, "noto");
  const cashToken = await notoFactory
    .newNoto(verifierCentralBank, {
      notary: verifierCentralBank,
      notaryMode: "basic",
    })
    .waitForDeploy();
  if (!cashToken) {
    logger.error("Failed to deploy the Noto cash token!");
    return false;
  }
  logger.log("Noto cash token deployed successfully!");

  // Step 2: Mint cash tokens
  logger.log("Step 2: Minting 2000 units of cash to central bank...");
  const mintReceipt = await cashToken
    .mint(verifierCentralBank, {
      to: verifierCentralBank,
      amount: 2000,
      data: "0x",
    })
    .waitForReceipt();
  if (!mintReceipt) {
    logger.error("Failed to mint cash tokens!");
    return false;
  }
  logger.log("Successfully minted 2000 units of cash to central bank!");
  let balanceCentralBank = await cashToken.balanceOf(verifierCentralBank, {
    account: verifierCentralBank.lookup,
  });
  logger.log(
    `Central bank State: ${balanceCentralBank.totalBalance} units of cash, ${balanceCentralBank.totalStates} states, overflow: ${balanceCentralBank.overflow}`
  );

  // Step 3: Transfer cash to bank1
  logger.log("Step 3: Transferring 1000 units of cash from central bank to bank1...");
  const transferToBank1 = await cashToken
    .transfer(verifierCentralBank, {
      to: verifierBank1,
      amount: 1000,
      data: "0x",
    })
    .waitForReceipt();
  if (!transferToBank1) {
    logger.error("Failed to transfer cash to bank1!");
    return false;
  }
  logger.log("Successfully transferred 1000 units of cash to bank1!");
  let balanceBank1 = await cashToken.balanceOf(verifierCentralBank, {
    account: verifierBank1.lookup,
  });
  logger.log(
    `Bank1 State: ${balanceBank1.totalBalance} units of cash, ${balanceBank1.totalStates} states, overflow: ${balanceBank1.overflow}`
  );

  // Step 4: Transfer cash to bank1 from bank2
  logger.log("Step 4: Transferring 800 units of cash from bank1 to bank2...");
  const transferToBank2 = await cashToken
    .using(bank1)
    .transfer(verifierBank1, {
      to: verifierBank2,
      amount: 800,
      data: "0x",
    })
    .waitForReceipt();
  if (!transferToBank2) {
    logger.error("Failed to transfer cash to bank2!");
    return false;
  }
  logger.log("Successfully transferred 800 units of cash to bank2!");
  let balanceBank2 = await cashToken.balanceOf(verifierCentralBank, {
    account: verifierBank2.lookup,
  });
  logger.log(
    `Bank2 State: ${balanceBank2.totalBalance} units of cash, ${balanceBank2.totalStates} states, overflow: ${balanceBank2.overflow}`
  );

  // All steps completed successfully
  logger.log("All operations completed successfully!");
  return true;
}

// Execute the main function if this file is run directly
if (require.main === module) {
  main()
    .then((success: boolean) => {
      process.exit(success ? 0 : 1); // Exit with 0 for success, 1 for failure
    })
    .catch((err) => {
      logger.error("Exiting due to an uncaught error:", err);
      process.exit(1); // Exit with status 1 for any uncaught errors
    });
}
