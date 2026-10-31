// Version-specific, reference-guided metadata for the original 1.0.2.0
// Crimson Skies SafeDisc edition. No original executable bytes embedded.
pub fn import_order(kernel:bool)->Result<Vec<i16>,String> {
    let input=include_str!("../python/unwrapper/permutation_metadata.txt");
    let prefix=if kernel {"KERNEL32.dll:"} else {"USER32.dll:"};
    let line=input.lines().find(|l|l.starts_with(prefix))
        .ok_or("missing original import metadata")?;
    let values=line.split_once("permutation=[")
        .ok_or("missing original import permutation")?.1;
    let values=values.trim().strip_suffix(']')
        .ok_or("unterminated original import permutation")?;
    let order=values.split(',').map(|v|
        v.trim().parse::<i16>()
            .map_err(|_|"bad original import metadata".to_string()))
        .collect::<Result<Vec<_>,_>>()?;
    let n=if kernel {74usize}else{62};
    if order.len()!=n{return Err("original import permutation length mismatch".into());}
    let mut seen=vec![false;n];
    let mut zeroes=0;
    for &v in &order{
        if v==-1{zeroes+=1;continue;}
        if v<=0 || v as usize>=n || seen[v as usize]{
            return Err("original import index repeated or out of bounds".into());
        }
        seen[v as usize]=true;
    }
    if zeroes!=1 || !seen[1..].iter().all(|v|*v) {
        return Err("original import permutation is not bijective".into());
    }
    Ok(order)
}

pub fn callsites()->Result<Vec<u32>,String>{
    let input=include_str!("../python/unwrapper/import_site_rvas.txt");
    let mut sites=Vec::new();
    for token in input.split_whitespace(){
        let at=u32::from_str_radix(token,16)
            .map_err(|_|"bad original callsite RVA metadata")?;
        if sites.last().is_some_and(|prev|at<=*prev){
            return Err("original callsite RVAs are not ascending".into());
        }
        sites.push(at);
    }
    if sites.len()!=245 || sites.iter().map(|&s|u64::from(s)).sum::<u64>()!=211_661_056 {
        return Err("original callsite list failed integrity checks".into());
    }
    Ok(sites)
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn original_import_permutations_are_bijective(){
        assert_eq!(import_order(true).unwrap().len(),74);
        assert_eq!(import_order(false).unwrap().len(),62);
    }
    #[test]
    fn original_callsite_list_is_complete(){
        assert_eq!(callsites().unwrap().len(),245);
    }
}
