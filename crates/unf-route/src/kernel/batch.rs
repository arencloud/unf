//! One bounded streaming host snapshot for a selected attachment inventory.
//! Retains expected keys and seen bits, never the unrelated host route table.

use std::time::Duration;

use super::{
    BTreeMap, BorrowedFd, File, IpAddr, Ipv4Addr, Ipv6Addr, NativeRoutePlan, NeighborSpec,
    NeighbourMessage, RouteError, RouteKey, RouteMessage, RouteMessageBuilder, RouteSpec,
    TryStreamExt, connect, neighbor_destination, neighbor_exact, netlink, route_exact, route_key,
    route_message_key, run_in_namespace,
};

const MAX_SELECTED_KEYS: usize = 131_072;
const MAX_MESSAGES: usize = 1_048_576;
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);
type NeighborKey = (IpAddr, u32);

struct SelectedState {
    routes: BTreeMap<RouteKey, (RouteSpec, bool)>,
    neighbors: BTreeMap<NeighborKey, (NeighborSpec, bool)>,
    messages: usize,
}

impl SelectedState {
    fn new<'a>(plans: impl Iterator<Item = &'a NativeRoutePlan>) -> Result<Self, RouteError> {
        let mut state = Self {
            routes: BTreeMap::new(),
            neighbors: BTreeMap::new(),
            messages: 0,
        };
        for plan in plans {
            state.add(plan.host_routes, plan.host_neighbors)?;
        }
        Ok(state)
    }

    fn add(
        &mut self,
        routes: impl IntoIterator<Item = RouteSpec>,
        neighbors: impl IntoIterator<Item = NeighborSpec>,
    ) -> Result<(), RouteError> {
        for route in routes {
            if self.routes.len() >= MAX_SELECTED_KEYS
                || self
                    .routes
                    .insert(route_key(&route), (route, false))
                    .is_some()
            {
                return Err(invalid("duplicate or over-budget selected host route keys"));
            }
        }
        for neighbor in neighbors {
            let key = (neighbor.destination, neighbor.output_interface);
            if self.neighbors.len() >= MAX_SELECTED_KEYS
                || self.neighbors.insert(key, (neighbor, false)).is_some()
            {
                return Err(invalid(
                    "duplicate or over-budget selected host neighbor keys",
                ));
            }
        }
        Ok(())
    }

    fn charge(&mut self) -> Result<(), RouteError> {
        if self.messages >= MAX_MESSAGES {
            return Err(invalid("host route snapshot exceeds message budget"));
        }
        self.messages += 1;
        Ok(())
    }

    fn route(&mut self, message: &RouteMessage) -> Result<(), RouteError> {
        self.charge()?;
        let Some((expected, seen)) = self.routes.get_mut(&route_message_key(message)) else {
            return Ok(());
        };
        if *seen || !route_exact(message, expected) {
            return Err(invalid(
                "selected host route is duplicate or conflicts with its plan",
            ));
        }
        *seen = true;
        Ok(())
    }

    fn neighbor(&mut self, message: &NeighbourMessage) -> Result<(), RouteError> {
        self.charge()?;
        let Some(destination) = neighbor_destination(message) else {
            return Ok(());
        };
        let Some((expected, seen)) = self
            .neighbors
            .get_mut(&(destination, message.header.ifindex))
        else {
            return Ok(());
        };
        if *seen || !neighbor_exact(message, expected) {
            return Err(invalid(
                "selected host neighbor is duplicate or conflicts with its plan",
            ));
        }
        *seen = true;
        Ok(())
    }

    fn complete(&self) -> Result<(), RouteError> {
        if self.routes.values().any(|(_, seen)| !seen)
            || self.neighbors.values().any(|(_, seen)| !seen)
        {
            return Err(invalid("selected host route snapshot is incomplete"));
        }
        Ok(())
    }
}

pub(crate) async fn verify_host<'a>(
    namespace: BorrowedFd<'_>,
    plans: impl Iterator<Item = &'a NativeRoutePlan>,
) -> Result<(), RouteError> {
    let selected = SelectedState::new(plans)?;
    let namespace = namespace
        .try_clone_to_owned()
        .map(File::from)
        .map_err(|error| invalid(&format!("duplicate batch host namespace: {error}")))?;
    run_in_namespace(namespace, move || async move {
        tokio::time::timeout(SNAPSHOT_TIMEOUT, read_namespace(selected))
            .await
            .map_err(|_| invalid("host route snapshot deadline exceeded"))?
    })
    .await
}

async fn read_namespace(mut selected: SelectedState) -> Result<(), RouteError> {
    let handle = connect("open batch route connection")?;
    for request in [
        RouteMessageBuilder::<Ipv4Addr>::new().build(),
        RouteMessageBuilder::<Ipv6Addr>::new().build(),
    ] {
        let mut stream = handle.route().get(request).execute();
        while let Some(message) = stream
            .try_next()
            .await
            .map_err(|error| netlink("stream batch host routes", &error))?
        {
            selected.route(&message)?;
        }
    }
    let mut stream = handle.neighbours().get().execute();
    while let Some(message) = stream
        .try_next()
        .await
        .map_err(|error| netlink("stream batch host neighbors", &error))?
    {
        selected.neighbor(&message)?;
    }
    selected.complete()
}

pub(crate) async fn verify_peer(
    namespace: BorrowedFd<'_>,
    plan: &NativeRoutePlan,
) -> Result<(), RouteError> {
    let namespace = namespace
        .try_clone_to_owned()
        .map(File::from)
        .map_err(|error| invalid(&format!("duplicate batch peer namespace: {error}")))?;
    let mut selected = SelectedState::new(std::iter::empty())?;
    selected.add(plan.container_routes, plan.container_neighbors)?;
    run_in_namespace(namespace, move || async move {
        tokio::time::timeout(SNAPSHOT_TIMEOUT, read_namespace(selected))
            .await
            .map_err(|_| invalid("peer route snapshot deadline exceeded"))?
    })
    .await
}

fn invalid(message: &str) -> RouteError {
    RouteError::Readback(message.into())
}

#[cfg(test)]
mod tests;
