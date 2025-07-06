import React, { useState } from "react";
import { Dialog } from "../../packages/excalidraw/components/Dialog";
import { Island } from "../../packages/excalidraw/components/Island";
import { TextField } from "../../packages/excalidraw/components/TextField";
import { FilledButton } from "../../packages/excalidraw/components/FilledButton";
import { useAtom } from "jotai";
import { storageConfigAtom } from "../app-jotai";

export type StorageType = "default" | "kv" | "s3" | "indexed-db";

const StorageSettingsDialog = ({ onClose }: { onClose: () => void }) => {
  const storedToken = localStorage.getItem("token"); // 如果未登录，无法使用后端存储
  const [config, setConfig] = useAtom(storageConfigAtom);
  const [storageType, setStorageType] = useState<StorageType>(
    !storedToken && config.type === "default" ? "indexed-db" : config.type,
  );

  // Local state for form inputs
  const [kvUrl, setKvUrl] = useState(config.kvUrl || "");
  const [kvApiToken, setKvApiToken] = useState(config.kvApiToken || "");
  const [s3AccessKeyId, setS3AccessKeyId] = useState(
    config.s3AccessKeyId || "",
  );
  const [s3SecretAccessKey, setS3SecretAccessKey] = useState(
    config.s3SecretAccessKey || "",
  );
  const [s3Region, setS3Region] = useState(config.s3Region || "");
  const [s3BucketName, setS3BucketName] = useState(config.s3BucketName || "");

  const handleSave = () => {
    setConfig({
      type: storageType,
      kvUrl,
      kvApiToken,
      s3AccessKeyId,
      s3SecretAccessKey,
      s3Region,
      s3BucketName,
    });
    onClose();
  };

  const renderForm = () => {
    switch (storageType) {
      case "kv":
        return (
          <>
            <TextField
              label="KV URL"
              value={kvUrl}
              placeholder="Your Cloudflare KV URL"
              onChange={setKvUrl}
            />
            <TextField
              label="API Token"
              value={kvApiToken}
              placeholder="Your Cloudflare API Token"
              onChange={setKvApiToken}
            />
          </>
        );
      case "s3":
        return (
          <>
            <TextField
              label="Access Key ID"
              value={s3AccessKeyId}
              placeholder="Your AWS Access Key ID"
              onChange={setS3AccessKeyId}
            />
            <TextField
              label="Secret Access Key"
              value={s3SecretAccessKey}
              placeholder="Your AWS Secret Access Key"
              onChange={setS3SecretAccessKey}
            />
            <TextField
              label="Region"
              value={s3Region}
              placeholder="e.g., us-east-1"
              onChange={setS3Region}
            />
            <TextField
              label="Bucket Name"
              value={s3BucketName}
              placeholder="Your S3 Bucket Name"
              onChange={setS3BucketName}
            />
          </>
        );
      case "indexed-db":
        return (
          <p>
            Your canvases are stored securely in your browser's local database.
            They are not synced online.
          </p>
        );
      case "default":
      default:
        return (
          <p>
            {!storedToken
              ? "You must be logged in to use the default backend storage. Please log in and try again."
              : "Your data is stored on the default backend of this Excalidraw instance. This requires you to be logged in."}
          </p>
        );
    }
  };

  return (
    <Dialog
      onCloseRequest={onClose}
      title={"Data Source Settings"}
      className="storage-settings-dialog"
    >
      <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
        <p>
          Security Warning: Sensitive keys are stored only in your browser's
          session storage and are cleared when you close the tab.
        </p>

        <select
          value={storageType}
          onChange={(e) => setStorageType(e.target.value as StorageType)}
          style={{
            padding: "0.5rem",
            borderRadius: "var(--border-radius-lg)",
            border: "1px solid var(--color-border)",
          }}
        >
          <option value="indexed-db">Browser (IndexedDB)</option>
          <option
            value="default"
            disabled={!storedToken}
            title={
              !storedToken ? "Please log in to use this option" : undefined
            }
          >
            Default Backend (Online)
          </option>
          <option value="kv">Cloudflare KV (Online)</option>
          <option value="s3">Amazon S3 (Online)</option>
        </select>

        <Island style={{ padding: "1rem" }}>
          <div
            style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}
          >
            {renderForm()}
          </div>
        </Island>

        <div
          style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}
        >
          <FilledButton color="primary" label={"Save"} onClick={handleSave} />
        </div>
      </div>
    </Dialog>
  );
};

export default StorageSettingsDialog;
