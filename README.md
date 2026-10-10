# No Mod Lock

**Play with mods without losing achievements, unlock progress and run records.** This mod removes the restrictions
Noita normally imposes when mods are enabled, by **patching the engine's own decision code** (never by editing game
data or save files). Patches are found by **byte signature**, so they keep working across game updates that only move
code around.

装上 Mod 也能正常解锁成就、保留进度与战绩。本 mod 通过**给引擎自己的判断代码打补丁**来解除限制（不改动任何游戏
数据、不改存档），补丁位置**按字节特征搜索**，所以游戏更新不修改mod判断代码时仍然有效。

---

## 功能

- 使用 Mod 时**不再禁用成就**。
- 使用 Mod 时**照常记录本局战绩**（胜负、连胜、统计）。

## 安装

1. 需要正版 Windows PC 版 Noita，并在启动器里勾选 **允许不安全的 Mod / unsafe mods**。
2. 把本仓库放进游戏的 mods 目录，**文件夹名必须是 `no_mod_lock`**（如果在release里下载，只移动no mod lock文件夹即可）：

   ```
   <Steam 安装位置>\steamapps\common\Noita\mods\no_mod_lock\
   ```


3. 启动游戏 → **Mods** → 勾选 **No Mod Lock** → 开局。

## 说明

- 补丁特征表放在 [`files/signatures.txt`](files/signatures.txt)；如果游戏更新后某个补丁找不到，
  日志里会说明是哪一个，把特征补上即可（详细原理见 [详细说明.md](详细说明.md)）。
- 需要 `request_no_api_restrictions="1"`（要用 FFI 读写引擎内存），因此**无法上传到 Steam 创意工坊**，
  这里通过 GitHub 分发。

## 详细文档

原理、补丁点、特征表格式与排查方法都在 **[详细说明.md](详细说明.md)** 里。

## 许可

见 `LICENSE`
