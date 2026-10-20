//! Official-market policy only; ordinary transfers and third-party purchases are unaffected.
//! The buyer adds this fee to the seller payout. No floating-point monetary arithmetic.
pub const BASIS_POINTS: u64 = 200;
pub const DENOMINATOR: u64 = 10_000;
pub const MIN_OUTPUT_ZAT: u64 = 546;
pub const MAX_MONEY_ZAT: u64 = 2_100_000_000_000_000;
// Rounding up to one zatoshi allows this first price to produce a 546-zat fee.
pub const MIN_PRICE_ZAT: u64 = 27_251;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    pub seller_zat: u64,
    pub market_fee_zat: u64,
    /// Excludes network fees; a standard carrier is supplied by the seller input.
    pub purchase_total_zat: u64,
}

pub fn quote(price: u64) -> Result<Quote, &'static str> {
    if price == 0 || price > MAX_MONEY_ZAT { return Err("invalid market price"); }
    let fee = ((u128::from(price) * u128::from(BASIS_POINTS)
        + u128::from(DENOMINATOR - 1)) / u128::from(DENOMINATOR)) as u64;
    if fee < MIN_OUTPUT_ZAT { return Err("market price below minimum fee-output threshold"); }
    let total = price.checked_add(fee).ok_or("market amount overflow")?;
    if total > MAX_MONEY_ZAT { return Err("market total exceeds money range"); }
    Ok(Quote { seller_zat: price, market_fee_zat: fee, purchase_total_zat: total })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn buyer_pays_two_percent_without_reducing_seller_proceeds() {
        assert_eq!(quote(100_000_000).unwrap(), Quote {
            seller_zat: 100_000_000, market_fee_zat: 2_000_000,
            purchase_total_zat: 102_000_000,
        });
        assert_eq!(quote(5_000_000).unwrap().market_fee_zat, 100_000);
    }
    #[test]
    fn fractional_zatoshi_rounds_up_and_dust_is_not_subsidized() {
        assert!(quote(MIN_PRICE_ZAT - 1).is_err());
        assert_eq!(quote(MIN_PRICE_ZAT).unwrap().market_fee_zat, MIN_OUTPUT_ZAT);
        assert_eq!(quote(100_000_001).unwrap().market_fee_zat, 2_000_001);
    }
    #[test]
    fn malformed_or_unfundable_amounts_are_rejected() {
        for p in [0, 1, MAX_MONEY_ZAT, MAX_MONEY_ZAT + 1, u64::MAX] {
            assert!(quote(p).is_err(), "{p}");
        }
    }
    #[test]
    fn fee_is_exact_ceil_with_less_than_one_zatoshi_rounding() {
        for price in MIN_PRICE_ZAT..MIN_PRICE_ZAT + 100_000 {
            let q = quote(price).unwrap();
            assert!(q.market_fee_zat * DENOMINATOR >= price * BASIS_POINTS);
            assert!((q.market_fee_zat - 1) * DENOMINATOR < price * BASIS_POINTS);
            assert_eq!(q.purchase_total_zat - q.market_fee_zat, price);
        }
    }
}
