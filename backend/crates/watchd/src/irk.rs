//! IRK verification adapted from watch-unlock-linux.
//!
//! 手表广播使用可解析私有地址（RPA），地址每 ~15 分钟轮换。
//! IRK 能解析地址，但不能证明实时佩戴状态，也不能防重放或中继。

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{bail, Result};

/// 蓝牙地址哈希函数 ah(irk, prand)：
/// AES-128-ECB(13 字节 0x00 ‖ prand[3]) 加密结果的低 3 字节。
/// 参考：Bluetooth Core Spec Vol 3 Part H 2.2.4。
pub fn ah(irk: &[u8; 16], prand: &[u8; 3]) -> [u8; 3] {
    // 加密 13 字节 0x00 ‖ prand，取低 3 字节
    let mut block = GenericArray::from([0u8; 16]);
    block[13..].copy_from_slice(prand);
    let cipher = Aes128::new_from_slice(irk).expect("IRK 恒为 16 字节");
    cipher.encrypt_block(&mut block);
    [block[13], block[14], block[15]]
}

/// 解析 IRK hex（32 位，允许空格 / 冒号分隔），返回 16 字节密钥。
pub fn parse_irk_hex(value: &str) -> Result<[u8; 16]> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if cleaned.len() != 32 {
        bail!("IRK hex 长度应为 32，实际 {}", cleaned.len());
    }
    let bytes = hex::decode(&cleaned)?;
    let mut irk = [0u8; 16];
    irk.copy_from_slice(&bytes);
    Ok(irk)
}

/// 解析蓝牙地址字符串（"xx:xx:xx:xx:xx:xx"）。
fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let cleaned: String = mac.chars().filter(|c| *c != ':').collect();
    if cleaned.len() != 12 {
        return None;
    }
    let bytes = hex::decode(&cleaned).ok()?;
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// 校验该地址是否为"我的手表"（RPA 位检查 + IRK 哈希比对）。
pub fn is_my_watch(irk: &[u8; 16], mac: &str) -> bool {
    let Some(m) = parse_mac(mac) else {
        return false;
    };
    // RPA：地址最高两 bit 必须为 01
    if (m[0] >> 6) != 0b01 {
        return false;
    }
    let random_part = ((m[0] as u32 & 0x3f) << 16) | ((m[1] as u32) << 8) | m[2] as u32;
    if random_part == 0 || random_part == 0x3fffff {
        return false;
    }
    m[3..6] == ah(irk, &[m[0], m[1], m[2]])
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_irk_accepts_separators() {
        let a = parse_irk_hex("0011 2233 4455 6677 8899 aabb ccdd eeff").unwrap();
        let b = parse_irk_hex("00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff").unwrap();
        let c = parse_irk_hex("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn parse_irk_rejects_bad_input() {
        assert!(parse_irk_hex("0011").is_err());
        assert!(parse_irk_hex("zz112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn ah_returns_three_bytes() {
        let irk = [0x42u8; 16];
        assert_eq!(ah(&irk, &[1, 2, 3]).len(), 3);
    }

    #[test]
    fn bluetooth_sig_canonical_vector_and_forbidden_random_parts() {
        // Public Bluetooth Core Vol 3 Part H Appendix D.7 test vector.
        let key = parse_irk_hex("ec0234a357c8ad05341010a60a397d9b").unwrap();
        assert_eq!(ah(&key, &[0x70, 0x81, 0x94]), [0x0d, 0xfb, 0xaa]);
        assert!(is_my_watch(&key, "70:81:94:0D:FB:AA"));
        assert!(!is_my_watch(&[0; 16], "70:81:94:0D:FB:AA"));
        for prand in [[0x40, 0, 0], [0x7f, 0xff, 0xff]] {
            let hash = ah(&key, &prand);
            let address = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                prand[0], prand[1], prand[2], hash[0], hash[1], hash[2]);
            assert!(!is_my_watch(&key, &address));
        }
    }

    #[test]
    fn spec_vector_ah() {
        // Public deterministic fixture; the key is already in this API's AES byte order.
        // Identity import must normalize byte order before reaching this layer.
        let k = parse_irk_hex("100f0e0d0c0b0a090807060504030201").unwrap();
        assert_eq!(ah(&k, &[0x79, 0xCB, 0x92]), [0x70, 0xBE, 0xB3]);
    }

    #[test]
    fn spec_vector_rpa() {
        // Public fixture for complete RPA verification with the same normalized key.
        let k = parse_irk_hex("100f0e0d0c0b0a090807060504030201").unwrap();
        assert!(is_my_watch(&k, "79:CB:92:70:BE:B3"));
        assert!(is_my_watch(&k, "58:9B:3E:A3:5B:24"));
        // 错误 IRK 必须拒绝
        let wrong = parse_irk_hex("100f0e0d0c0b0a090807060504030202").unwrap();
        assert!(!is_my_watch(&wrong, "79:CB:92:70:BE:B3"));
    }

    #[test]
    fn rejects_non_rpa_and_malformed() {
        let irk = [0u8; 16];
        // 0x80 最高两 bit = 10，不是 RPA，必须拒绝
        assert!(!is_my_watch(&irk, "80:11:22:33:44:55"));
        assert!(!is_my_watch(&irk, "not-a-mac"));
    }
}
