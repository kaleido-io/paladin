import https from "https";
import PaladinClient, {
  PenteFactory,
} from "@lfdecentralizedtrust-labs/paladin-sdk";
import { checkDeploy } from "paladin-example-common";
import storageJson from "./abis/Storage.json";
import { PrivateStorage } from "./helpers/storage";

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
  // Get verifiers for each node
  const [verifierCentralBank] = centralBank.getVerifiers("member@central-bank");
  const [verifierBank1] = bank1.getVerifiers("member@bank1");
  const [verifierBank2] = bank2.getVerifiers("outsider@bank2");

  // Step 1: Create a privacy group for members
  logger.log("Creating a privacy group for central bank and bank1...");
  const penteFactory = new PenteFactory(centralBank, "pente");
  const memberPrivacyGroup = await penteFactory.newPrivacyGroup({
    members: [verifierCentralBank, verifierBank1],
    evmVersion: "shanghai",
    externalCallsEnabled: true,
  }).waitForDeploy();
  if (!checkDeploy(memberPrivacyGroup)) return false;

  logger.log(`Privacy group created, ID: ${memberPrivacyGroup?.group.id}`);

  // Step 2: Deploy a smart contract within the privacy group
  logger.log("Deploying a smart contract to the privacy group...");
  const contractAddress = await memberPrivacyGroup.deploy({
    abi: storageJson.abi,
    bytecode: storageJson.bytecode,
    from: verifierCentralBank.lookup,
  }).waitForDeploy();
  if (!contractAddress) {
    logger.error("Failed to deploy the contract. No address returned.");
    return false;
  }

  logger.log(`Contract deployed successfully! Address: ${contractAddress}`);

  // Step 3: Use the deployed contract for private storage
  const privateStorageContract = new PrivateStorage(
    memberPrivacyGroup,
    contractAddress
  );

  // Store a value in the contract
  const valueToStore = 125; // Example value to store
  logger.log(`Storing a value "${valueToStore}" in the contract...`);
  const storeReceipt = await privateStorageContract.sendTransaction({
    from: verifierCentralBank.lookup,
    function: "store",
    data: { num: valueToStore },
  }).waitForReceipt();
  logger.log(
    "Value stored successfully! Transaction hash:",
    storeReceipt?.transactionHash
  );

  // Retrieve the value as central bank
  logger.log("Central bank retrieving the value from the contract...");
  const retrievedValueCentralBank = await privateStorageContract.call({
    from: verifierCentralBank.lookup,
    function: "retrieve",
  });
  logger.log(
    "Central bank retrieved the value successfully:",
    retrievedValueCentralBank["value"]
  );

  // Retrieve the value as bank1
  logger.log("bank1 retrieving the value from the contract...");
  const retrievedValueBank1 = await privateStorageContract
    .using(bank1)
    .call({
      from: verifierBank1.lookup,
      function: "retrieve",
    });
  logger.log(
    "Bank1 retrieved the value successfully:",
    retrievedValueBank1["value"]
  );

  // Attempt to retrieve the value as bank2 (outsider)
  try {
    logger.log("Bank2 (outsider) attempting to retrieve the value...");
    await privateStorageContract.using(bank2).call({
      from: verifierBank2.lookup,
      function: "retrieve",
    });
    logger.error(
      "Bank2 (outsider) should not have access to the privacy group!"
    );
    return false;
  } catch (error) {
    logger.info(
      "Expected behavior - Bank2 (outsider) cannot retrieve the data from the privacy group. Access denied."
    );
  }

  logger.log("All steps completed successfully!");

  return true;
}

// Execute the main function when this file is run directly
if (require.main === module) {
  main()
    .then((success: boolean) => {
      process.exit(success ? 0 : 1); // Exit with status 0 for success, 1 for failure
    })
    .catch((err) => {
      logger.error("Exiting due to an uncaught error:", err);
      process.exit(1); // Exit with status 1 for any uncaught errors
    });
}
