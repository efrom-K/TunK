use anyhow::{anyhow, Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;

/// Запись таблицы маршрутизации IPv4 (как в выводе `route print -4`)
#[derive(Debug, Clone, PartialEq)]
pub struct RouteEntry {
    pub destination: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub interface: Ipv4Addr,
    pub metric: u32,
}

/// Разбирает текстовый вывод команды `route print -4` в список записей.
/// Строки с "On-link" и заголовки таблицы игнорируются.
pub fn parse_route_print_output(output: &str) -> Vec<RouteEntry> {
    let mut entries = Vec::new();

    for line in output.lines() {
        let columns: Vec<&str> = line.split_whitespace().collect();

        if columns.len() != 5 {
            continue;
        }

        let destination = columns[0].parse::<Ipv4Addr>();
        let netmask = columns[1].parse::<Ipv4Addr>();
        let gateway = columns[2].parse::<Ipv4Addr>();
        let interface = columns[3].parse::<Ipv4Addr>();
        let metric = columns[4].parse::<u32>();

        if let (Ok(destination), Ok(netmask), Ok(gateway), Ok(interface), Ok(metric)) =
            (destination, netmask, gateway, interface, metric)
        {
            entries.push(RouteEntry {
                destination,
                netmask,
                gateway,
                interface,
                metric,
            });
        }
    }

    entries
}

/// Находит маршрут по умолчанию (0.0.0.0/0) и возвращает адрес шлюза.
pub fn find_default_gateway(entries: &[RouteEntry]) -> Option<Ipv4Addr> {
    entries
        .iter()
        .find(|entry| entry.destination == Ipv4Addr::new(0, 0, 0, 0) && entry.netmask == Ipv4Addr::new(0, 0, 0, 0))
        .map(|entry| entry.gateway)
}

/// Аргументы для `route add <dest> mask <mask> <gateway> metric <metric>`
fn route_add_args(destination: Ipv4Addr, mask: Ipv4Addr, gateway: Ipv4Addr, metric: u32) -> Vec<String> {
    vec![
        "add".to_string(),
        destination.to_string(),
        "mask".to_string(),
        mask.to_string(),
        gateway.to_string(),
        "metric".to_string(),
        metric.to_string(),
    ]
}

/// Аргументы для `route delete <dest> mask <mask>`
fn route_delete_args(destination: Ipv4Addr, mask: Ipv4Addr) -> Vec<String> {
    vec![
        "delete".to_string(),
        destination.to_string(),
        "mask".to_string(),
        mask.to_string(),
    ]
}

/// Аргументы для `netsh interface ipv4 set interface <index> metric=<metric>`
fn netsh_set_metric_args(interface_index: u32, metric: u32) -> Vec<String> {
    vec![
        "interface".to_string(),
        "ipv4".to_string(),
        "set".to_string(),
        "interface".to_string(),
        interface_index.to_string(),
        format!("metric={}", metric),
    ]
}

/// Управление таблицей маршрутизации Windows через `route` и `netsh`.
pub struct RouteManager;

impl RouteManager {
    /// Возвращает текущую таблицу маршрутизации IPv4.
    pub fn get_routing_table() -> Result<Vec<RouteEntry>> {
        let output = Command::new("route")
            .args(["print", "-4"])
            .output()
            .context("Не удалось выполнить команду route print")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_route_print_output(&stdout))
    }

    /// Возвращает адрес шлюза по умолчанию текущей системы.
    pub fn get_default_gateway() -> Result<Ipv4Addr> {
        let table = Self::get_routing_table()?;
        find_default_gateway(&table).ok_or_else(|| anyhow!("Маршрут по умолчанию не найден в таблице маршрутизации"))
    }

    /// Устанавливает метрику для указанного сетевого интерфейса (по индексу).
    /// Меньшая метрика означает более высокий приоритет маршрута.
    pub fn set_interface_metric(interface_index: u32, metric: u32) -> Result<()> {
        let status = Command::new("netsh")
            .args(netsh_set_metric_args(interface_index, metric))
            .status()
            .context("Не удалось выполнить netsh interface ipv4 set interface")?;

        if status.success() {
            Ok(())
        } else {
            Err(anyhow!("netsh завершился с кодом ошибки: {:?}", status.code()))
        }
    }

    /// Добавляет статический маршрут в таблицу маршрутизации.
    pub fn add_route(destination: Ipv4Addr, mask: Ipv4Addr, gateway: Ipv4Addr, metric: u32) -> Result<()> {
        let status = Command::new("route")
            .args(route_add_args(destination, mask, gateway, metric))
            .status()
            .context("Не удалось выполнить route add")?;

        if status.success() {
            Ok(())
        } else {
            Err(anyhow!("route add завершился с кодом ошибки: {:?}", status.code()))
        }
    }

    /// Удаляет статический маршрут из таблицы маршрутизации.
    pub fn delete_route(destination: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
        let status = Command::new("route")
            .args(route_delete_args(destination, mask))
            .status()
            .context("Не удалось выполнить route delete")?;

        if status.success() {
            Ok(())
        } else {
            Err(anyhow!("route delete завершился с кодом ошибки: {:?}", status.code()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ROUTE_PRINT: &str = "\
===========================================================================
Interface List
 15...00 ff 1e 3e 4d 5b ......TunK
  9...8c 16 45 12 34 56 ......Realtek PCIe GbE Family Controller
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
       192.168.1.0    255.255.255.0         On-link    192.168.1.50    281
     192.168.1.50  255.255.255.255         On-link    192.168.1.50    281
   192.168.1.255  255.255.255.255         On-link    192.168.1.50    281
===========================================================================
";

    #[test]
    fn test_parse_route_print_output() {
        let entries = parse_route_print_output(SAMPLE_ROUTE_PRINT);

        // "On-link" строки не парсятся как IP, поэтому остаётся только маршрут по умолчанию
        assert_eq!(entries.len(), 1);

        let default_route = &entries[0];
        assert_eq!(default_route.destination, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(default_route.netmask, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(default_route.gateway, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(default_route.interface, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(default_route.metric, 25);
    }

    #[test]
    fn test_find_default_gateway() {
        let entries = parse_route_print_output(SAMPLE_ROUTE_PRINT);
        let gateway = find_default_gateway(&entries);

        assert_eq!(gateway, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_find_default_gateway_missing() {
        let entries = vec![RouteEntry {
            destination: Ipv4Addr::new(10, 0, 0, 0),
            netmask: Ipv4Addr::new(255, 0, 0, 0),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            interface: Ipv4Addr::new(10, 0, 0, 5),
            metric: 10,
        }];

        assert_eq!(find_default_gateway(&entries), None);
    }

    #[test]
    fn test_parse_route_print_empty_input() {
        let entries = parse_route_print_output("");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_route_print_ignores_malformed_lines() {
        let input = "это не похоже на маршрут\n1 2 3\n";
        let entries = parse_route_print_output(input);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_route_add_args() {
        let args = route_add_args(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(192, 168, 1, 1),
            1,
        );

        assert_eq!(
            args,
            vec!["add", "1.2.3.4", "mask", "255.255.255.255", "192.168.1.1", "metric", "1"]
        );
    }

    #[test]
    fn test_route_delete_args() {
        let args = route_delete_args(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(255, 255, 255, 255));

        assert_eq!(args, vec!["delete", "1.2.3.4", "mask", "255.255.255.255"]);
    }

    #[test]
    fn test_netsh_set_metric_args() {
        let args = netsh_set_metric_args(15, 1);

        assert_eq!(args, vec!["interface", "ipv4", "set", "interface", "15", "metric=1"]);
    }

    #[test]
    fn test_get_routing_table_real_system() {
        // Команда `route print` только читает таблицу маршрутизации и безопасна для запуска в тестах.
        let table = RouteManager::get_routing_table().expect("route print должен выполниться успешно");

        // На любой системе Windows должен существовать маршрут по умолчанию.
        assert!(find_default_gateway(&table).is_some());
    }
}
