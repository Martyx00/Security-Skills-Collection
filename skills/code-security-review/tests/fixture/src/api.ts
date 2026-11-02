// TypeScript: the Node idioms, typed - and imported the way TypeScript imports.
import { exec } from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";

export function digest(d: Buffer): Buffer {                 // EXPECT-FUNC: digest
  return crypto.createHash("md5").update(d).digest();       // EXPECT: CRY-002
}

export function listDir(dir: string): void {                // EXPECT-FUNC: listDir
  exec("ls " + dir);                                        // EXPECT: INJ-002
}

export function findUser(db: any, id: string): any {        // EXPECT-FUNC: findUser
  return db.query(`SELECT * FROM users WHERE id = ${id}`);  // EXPECT: INJ-003
}

export function readDoc(name: string): Buffer {             // EXPECT-FUNC: readDoc
  return fs.readFileSync("/srv/docs/" + name);              // EXPECT: INJ-004
}

export function proxy(url: string): Promise<any> {          // EXPECT-FUNC: proxy
  return fetch(url);                                        // EXPECT: INJ-005
}

export function insecureAgent(https: any): any {            // EXPECT-FUNC: insecureAgent
  return new https.Agent({ rejectUnauthorized: false });    // EXPECT: CRY-004
}

export function sessionId(): string {                       // EXPECT-FUNC: sessionId  // EXPECT: LOG-009
  return Math.random().toString(36);                        // EXPECT: OTH-002
}

const apiKey = "abcd1234efgh5678-not-real";                 // EXPECT: LOG-005

export function checkToken(token: string): boolean {        // EXPECT-FUNC: checkToken
  return token === apiKey;                                  // EXPECT: LOG-008
}

// Appended below so that nothing citing the lines above moves.
// Node's own documented idiom: the promise API imported by name, so no call
// says `fs.` - and a quoted option key. Each once recorded zero hits and
// absent-from-tree on a tree written this way.
import { readFile, rm } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import * as fsp from "node:fs/promises";

export async function readDocAsync(name: string): Promise<string> {   // EXPECT-FUNC: readDocAsync
  return readFile("/srv/docs/" + name, "utf8");                      // EXPECT: INJ-004
}

export async function readDocP(name: string): Promise<any> {         // EXPECT-FUNC: readDocP
  return fsp.readFile("/srv/docs/" + name);                          // EXPECT: INJ-004
}

export async function eraseDoc(name: string): Promise<void> {        // EXPECT-FUNC: eraseDoc
  await rm("/srv/docs/" + name, { force: true });                    // EXPECT: INJ-004
}

export function gitLog(ref: string): string {                        // EXPECT-FUNC: gitLog
  return execFileSync("git", ["log", ref]).toString();               // EXPECT: INJ-002
}

export function quotedAgent(https: any): any {                       // EXPECT-FUNC: quotedAgent
  return new https.Agent({ "rejectUnauthorized": false });           // EXPECT: CRY-004
}
