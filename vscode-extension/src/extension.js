const vscode = require("vscode");
const { Privatiser } = require("./privatiser");

const MAPPING_KEY = "privatiser.mappings";

function getPrivatiserConfig() {
  const cfg = vscode.workspace.getConfiguration("privatiser");
  const cats = vscode.workspace.getConfiguration("privatiser.categories");
  return {
    customWords: cfg.get("customWords") || [],
    allowlist: cfg.get("allowlist") || [],
    enabledCategories: {
      secrets: cats.get("secrets") !== false,
      network: cats.get("network") !== false,
      pii: cats.get("pii") !== false,
      aws: cats.get("aws") !== false,
      cloud: cats.get("cloud") !== false,
      identifiers: cats.get("identifiers") !== false,
    },
  };
}

function activate(context) {
  function getStoredMappings() {
    return context.workspaceState.get(MAPPING_KEY, {});
  }

  function storeMapping(fileName, mapping) {
    const all = getStoredMappings();
    all[fileName] = mapping;
    context.workspaceState.update(MAPPING_KEY, all);
  }

  function getMapping(fileName) {
    return getStoredMappings()[fileName] || null;
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("privatiser.anonymize", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const selection = editor.selection;
      if (selection.isEmpty) {
        return vscode.window.showWarningMessage("Privatiser: No text selected.");
      }
      const text = editor.document.getText(selection);
      const p = new Privatiser(getPrivatiserConfig());
      const { result, mapping } = p.anonymize(text);
      const count = Object.keys(mapping).length;
      if (count === 0) {
        return vscode.window.showInformationMessage("Privatiser: No sensitive data found.");
      }
      await editor.edit((e) => e.replace(selection, result));
      await vscode.env.clipboard.writeText(result);
      const fileName = editor.document.fileName;
      storeMapping(fileName, { ...(getMapping(fileName) || {}), ...mapping });
      vscode.window.showInformationMessage(`Privatiser: Anonymized ${count} item(s). Copied to clipboard.`);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("privatiser.copyAnonymized", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const selection = editor.selection;
      if (selection.isEmpty) {
        return vscode.window.showWarningMessage("Privatiser: No text selected.");
      }
      const text = editor.document.getText(selection);
      const p = new Privatiser(getPrivatiserConfig());
      const { result, mapping } = p.anonymize(text);
      const count = Object.keys(mapping).length;
      if (count === 0) {
        return vscode.window.showInformationMessage("Privatiser: No sensitive data found.");
      }
      await vscode.env.clipboard.writeText(result);
      const fileName = editor.document.fileName;
      storeMapping(fileName, { ...(getMapping(fileName) || {}), ...mapping });
      vscode.window.showInformationMessage(`Privatiser: Anonymized ${count} item(s) copied to clipboard — editor unchanged.`);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("privatiser.anonymizeFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const doc = editor.document;
      const text = doc.getText();
      const p = new Privatiser(getPrivatiserConfig());
      const { result, mapping } = p.anonymize(text);
      const count = Object.keys(mapping).length;
      if (count === 0) {
        return vscode.window.showInformationMessage("Privatiser: No sensitive data found.");
      }
      await vscode.env.clipboard.writeText(result);
      storeMapping(doc.fileName, mapping);
      vscode.window.showInformationMessage(`Privatiser: Anonymized ${count} item(s). Copied to clipboard — file unchanged.`);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("privatiser.deanonymize", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const selection = editor.selection;
      if (selection.isEmpty) {
        return vscode.window.showWarningMessage("Privatiser: No text selected.");
      }
      const mapping = getMapping(editor.document.fileName);
      if (!mapping) {
        return vscode.window.showWarningMessage("Privatiser: No mapping found. Anonymize something first.");
      }
      const text = editor.document.getText(selection);
      const result = new Privatiser().deanonymize(text, mapping);
      await editor.edit((e) => e.replace(selection, result));
      vscode.window.showInformationMessage("Privatiser: Restored original values.");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("privatiser.deanonymizeFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      const doc = editor.document;
      const mapping = getMapping(doc.fileName);
      if (!mapping) {
        return vscode.window.showWarningMessage("Privatiser: No mapping found. Anonymize something first.");
      }
      const text = doc.getText();
      const result = new Privatiser().deanonymize(text, mapping);
      const fullRange = new vscode.Range(doc.positionAt(0), doc.positionAt(text.length));
      await editor.edit((e) => e.replace(fullRange, result));
      vscode.window.showInformationMessage("Privatiser: Restored original values in entire file.");
    })
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
