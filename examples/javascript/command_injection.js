// CWE-78: command injection via process.argv -> child_process.exec.
const { exec, execSync } = require("child_process");
const fs = require("fs");

const target = process.argv[2];
exec(target);

function runEnv() {
  const cmd = process.env.CMD;
  execSync(cmd);
}

function readUser(path) {
  const data = fs.readFileSync(path, "utf8");
  eval(data);
}

module.exports = { runEnv, readUser };
