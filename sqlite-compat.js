/**
 * sqlite-compat.js
 * better-sqlite3 互換ラッパー（node-sqlite3-wasm使用）
 * Termux/Android でネイティブビルドなしで動作
 * 
 * better-sqlite3 と node-sqlite3-wasm の違い:
 *   better-sqlite3: stmt.run(a, b, c)  ← spread
 *   node-sqlite3-wasm: stmt.run([a, b, c]) ← array
 * このラッパーで吸収する
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { Database: _Database } = require('node-sqlite3-wasm');

class CompatStatement {
  constructor(stmt) {
    this._stmt = stmt;
  }

  // better-sqlite3: stmt.run(a, b, c) or stmt.run([a,b,c])
  run(...args) {
    const params = args.length === 1 && Array.isArray(args[0]) ? args[0] : args;
    return this._stmt.run(params);
  }

  // better-sqlite3: stmt.get(a, b, c) or stmt.get([a,b,c])
  get(...args) {
    const params = args.length === 1 && Array.isArray(args[0]) ? args[0] : args;
    return this._stmt.get(params) ?? undefined;
  }

  // better-sqlite3: stmt.all(a, b, c) or stmt.all([a,b,c])
  all(...args) {
    const params = args.length === 1 && Array.isArray(args[0]) ? args[0] : args;
    return this._stmt.all(params);
  }
}

class CompatDatabase {
  constructor(filepath) {
    this._db = new _Database(filepath);
  }

  prepare(sql) {
    return new CompatStatement(this._db.prepare(sql));
  }

  exec(sql) {
    return this._db.exec(sql);
  }

  close() {
    return this._db.close();
  }
}

export default CompatDatabase;
