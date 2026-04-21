use crate::session::{context::SessionContext, response::Response, state::SessionState};

/// Information about a newsgroup needed for GROUP/NEXT/LAST/STAT responses.
pub struct GroupData {
    pub name: String,
    pub count: u64,
    pub low: u64,
    pub high: u64,
    /// Article numbers present in the group (sorted ascending).
    pub article_numbers: Vec<u64>,
}

/// Convert a cache entry into the GroupData expected by group handlers.
/// `article_numbers` is provided by the caller (from the article number store).
pub fn group_data_from_cache(
    meta: &crate::store::group_cache::GroupMetadata,
    article_numbers: Vec<u64>,
) -> GroupData {
    GroupData {
        name: meta.name.clone(),
        count: meta.count,
        low: meta.low,
        high: meta.high,
        article_numbers,
    }
}

/// GROUP groupname: select a group and return its stats.
///
/// On success: updates `ctx.current_group` and `ctx.current_article_number`
/// (to the first article number, or 0 for an empty group).
/// Returns 211 with "count low high name", or 411 if `group_data` is `None`.
pub fn group_select(ctx: &mut SessionContext, group_data: Option<&GroupData>) -> Response {
    match group_data {
        None => Response::no_such_newsgroup(),
        Some(gd) => {
            ctx.current_group = usenet_ipfs_core::article::GroupName::new(gd.name.clone()).ok();
            ctx.current_article_number = Some(gd.article_numbers.first().copied().unwrap_or(0));
            ctx.state = SessionState::GroupSelected;
            Response::group_selected(&gd.name, gd.count, gd.low, gd.high)
        }
    }
}

/// NEXT: advance to the next article in the current group.
///
/// Requires `GroupSelected` state. Returns 223 with the new article number and
/// a placeholder message-id, or 421 if the cursor is already at the last article,
/// or 412 if no group is selected.
pub fn next_article(ctx: &mut SessionContext, group_data: Option<&GroupData>) -> Response {
    if !ctx.state.group_selected() {
        return Response::no_newsgroup_selected();
    }
    let gd = match group_data {
        Some(gd) => gd,
        None => return Response::no_next_article(),
    };
    let current = ctx.current_article_number.unwrap_or(0);
    let next = gd.article_numbers.iter().find(|&&n| n > current).copied();
    match next {
        Some(n) => {
            ctx.current_article_number = Some(n);
            Response::article_exists(n, &format!("<{n}@placeholder>"))
        }
        None => Response::no_next_article(),
    }
}

/// LAST: go back to the previous article in the current group.
///
/// Requires `GroupSelected` state. Returns 223 with the new article number and
/// a placeholder message-id, or 422 if the cursor is already at the first article,
/// or 412 if no group is selected.
pub fn last_article(ctx: &mut SessionContext, group_data: Option<&GroupData>) -> Response {
    if !ctx.state.group_selected() {
        return Response::no_newsgroup_selected();
    }
    let gd = match group_data {
        Some(gd) => gd,
        None => return Response::no_previous_article(),
    };
    let current = ctx.current_article_number.unwrap_or(0);
    let prev = gd
        .article_numbers
        .iter()
        .rev()
        .find(|&&n| n < current)
        .copied();
    match prev {
        Some(n) => {
            ctx.current_article_number = Some(n);
            Response::article_exists(n, &format!("<{n}@placeholder>"))
        }
        None => Response::no_previous_article(),
    }
}

/// STAT [msgid|number]: check whether an article exists; does not change cursor.
///
/// Returns 223 if the article exists (number form only; msgid form returns 430
/// as a stub). Returns 412 if no group is selected (number form without a
/// group), 423 if the number is not in the group, or 430 for an unknown
/// message-id.
pub fn stat_article(
    ctx: &mut SessionContext,
    group_data: Option<&GroupData>,
    arg: Option<&str>,
) -> Response {
    match arg {
        // Message-ID form: no group required; return 430 stub.
        Some(s) if s.starts_with('<') => Response::no_article_with_message_id(),
        // Number form (or no arg — use current article pointer).
        _ => {
            if !ctx.state.group_selected() {
                return Response::no_newsgroup_selected();
            }
            let gd = match group_data {
                Some(gd) => gd,
                None => return Response::no_article_with_number(),
            };
            let number: Option<u64> = match arg {
                Some(s) => s.parse().ok(),
                None => ctx.current_article_number,
            };
            match number {
                Some(n) if gd.article_numbers.contains(&n) => {
                    Response::article_exists(n, &format!("<{n}@placeholder>"))
                }
                _ => Response::no_article_with_number(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_ctx() -> SessionContext {
        SessionContext::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
            false,
            true,
            false,
        )
    }

    fn make_group(name: &str, numbers: Vec<u64>) -> GroupData {
        let low = numbers.first().copied().unwrap_or(1);
        let high = numbers.last().copied().unwrap_or(0);
        GroupData {
            name: name.into(),
            count: numbers.len() as u64,
            low,
            high,
            article_numbers: numbers,
        }
    }

    // ---- group_data_from_cache ----

    #[test]
    fn group_data_from_cache_maps_fields() {
        use crate::store::group_cache::GroupMetadata;
        let meta = GroupMetadata {
            name: "comp.lang.rust".to_string(),
            count: 42,
            low: 1,
            high: 42,
            description: "Rust".to_string(),
        };
        let nums = vec![1u64, 2, 3, 42];
        let gd = group_data_from_cache(&meta, nums.clone());
        assert_eq!(gd.name, "comp.lang.rust");
        assert_eq!(gd.count, 42);
        assert_eq!(gd.low, 1);
        assert_eq!(gd.high, 42);
        assert_eq!(gd.article_numbers, nums);
    }

    #[test]
    fn group_select_known() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        let resp = group_select(&mut ctx, Some(&gd));
        assert_eq!(resp.code, 211);
        assert!(ctx.current_group.is_some());
        assert_eq!(ctx.state, SessionState::GroupSelected);
    }

    #[test]
    fn group_select_unknown() {
        let mut ctx = make_ctx();
        let resp = group_select(&mut ctx, None);
        assert_eq!(resp.code, 411);
    }

    #[test]
    fn group_select_empty() {
        let mut ctx = make_ctx();
        let gd = make_group("empty.group", vec![]);
        let resp = group_select(&mut ctx, Some(&gd));
        assert_eq!(resp.code, 211);
        assert!(resp.text.starts_with("0 "));
    }

    #[test]
    fn next_advances_cursor() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        group_select(&mut ctx, Some(&gd));
        // cursor starts at 1 (first article)
        let resp = next_article(&mut ctx, Some(&gd));
        assert_eq!(resp.code, 223);
        assert_eq!(ctx.current_article_number, Some(2));
    }

    #[test]
    fn next_at_end_returns_421() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        group_select(&mut ctx, Some(&gd));
        // Advance cursor to last article.
        ctx.current_article_number = Some(3);
        let resp = next_article(&mut ctx, Some(&gd));
        assert_eq!(resp.code, 421);
    }

    #[test]
    fn last_retreats_cursor() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        group_select(&mut ctx, Some(&gd));
        ctx.current_article_number = Some(2);
        let resp = last_article(&mut ctx, Some(&gd));
        assert_eq!(resp.code, 223);
        assert_eq!(ctx.current_article_number, Some(1));
    }

    #[test]
    fn last_at_beginning_returns_422() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        group_select(&mut ctx, Some(&gd));
        // cursor is at 1 after group_select
        let resp = last_article(&mut ctx, Some(&gd));
        assert_eq!(resp.code, 422);
    }

    #[test]
    fn stat_without_group_returns_412() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        let resp = stat_article(&mut ctx, Some(&gd), Some("2"));
        assert_eq!(resp.code, 412);
    }

    #[test]
    fn stat_existing_number() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        group_select(&mut ctx, Some(&gd));
        let resp = stat_article(&mut ctx, Some(&gd), Some("2"));
        assert_eq!(resp.code, 223);
    }

    #[test]
    fn stat_missing_number() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        group_select(&mut ctx, Some(&gd));
        let resp = stat_article(&mut ctx, Some(&gd), Some("99"));
        assert_eq!(resp.code, 423);
    }

    #[test]
    fn stat_msgid_returns_430() {
        let mut ctx = make_ctx();
        let gd = make_group("comp.lang.rust", vec![1, 2, 3]);
        group_select(&mut ctx, Some(&gd));
        let resp = stat_article(&mut ctx, Some(&gd), Some("<foo@bar>"));
        assert_eq!(resp.code, 430);
    }
}
