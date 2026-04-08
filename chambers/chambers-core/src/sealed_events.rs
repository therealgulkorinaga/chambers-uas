use crate::types::*;

use chrono::{DateTime, Duration, Utc};
use geo::Contains;
use geojson::GeoJson;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};
use uuid::Uuid;

// ─── Geofence database ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AirspaceZone {
    pub name: String,
    pub airspace_class: String,
    pub zone_type: String, // "restricted", "tfr", "permitted"
    pub floor_ft_msl: f64,
    pub ceiling_ft_msl: f64,
    pub polygon: geo::Polygon<f64>,
}

pub struct GeofenceDatabase {
    pub zones: Vec<AirspaceZone>,
}

impl GeofenceDatabase {
    /// Load geofence zones from a GeoJSON file.
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        Self::from_geojson(&content)
    }

    /// Parse geofence zones from a GeoJSON string.
    pub fn from_geojson(geojson_str: &str) -> Result<Self, std::io::Error> {
        let geojson: GeoJson = geojson_str.parse().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("GeoJSON parse error: {}", e))
        })?;

        let mut zones = Vec::new();

        if let GeoJson::FeatureCollection(fc) = geojson {
            for feature in fc.features {
                let props = feature.properties.as_ref();
                let name = props
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed")
                    .to_string();
                let airspace_class = props
                    .and_then(|p| p.get("airspace_class"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let zone_type = props
                    .and_then(|p| p.get("zone_type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("restricted")
                    .to_string();
                let floor = props
                    .and_then(|p| p.get("floor_ft_msl"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let ceiling = props
                    .and_then(|p| p.get("ceiling_ft_msl"))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(f64::MAX);

                if let Some(geometry) = feature.geometry {
                    let geo_geom: Result<geo::Geometry<f64>, _> = geometry.value.try_into();
                    if let Ok(geo::Geometry::Polygon(polygon)) = geo_geom {
                        zones.push(AirspaceZone {
                            name,
                            airspace_class,
                            zone_type,
                            floor_ft_msl: floor,
                            ceiling_ft_msl: ceiling,
                            polygon,
                        });
                    }
                }
            }
        }

        Ok(Self { zones })
    }

    /// Check if a position is inside any restricted/TFR zone.
    /// Returns all zones the position is inside.
    pub fn check_position(&self, lat: f64, lon: f64, alt_ft_msl: f64) -> Vec<&AirspaceZone> {
        let point = geo::Point::new(lon, lat); // GeoJSON uses lon, lat order
        self.zones
            .iter()
            .filter(|zone| {
                zone.zone_type != "permitted"
                    && alt_ft_msl >= zone.floor_ft_msl
                    && alt_ft_msl <= zone.ceiling_ft_msl
                    && zone.polygon.contains(&point)
            })
            .collect()
    }

    /// Check if a position is inside the permitted flight area.
    pub fn is_in_permitted_area(&self, lat: f64, lon: f64) -> bool {
        let point = geo::Point::new(lon, lat);
        self.zones
            .iter()
            .filter(|z| z.zone_type == "permitted")
            .any(|z| z.polygon.contains(&point))
    }

    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }
}

// ─── Sealed event records ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEventRecord {
    pub id: String,
    pub event_type: SealedEventType,
    pub trigger_timestamp: DateTime<Utc>,
    pub detection_timestamp: DateTime<Utc>,
    pub trigger_source: String,
    pub preservation_scope: PreservationScope,
    pub context: serde_json::Value,
}

// ─── Sealed event engine ────────────────────────────────────────────────────

pub struct SealedEventEngine {
    geofence_db: Option<GeofenceDatabase>,
    fired_events: Vec<SealedEventRecord>,
    /// Deduplication: track last fire time per event type
    last_fired: HashMap<SealedEventType, DateTime<Utc>>,
    /// Deduplication window in seconds
    dedup_window_secs: i64,
    /// Geofence boundary for violation detection
    geofence_max_distance_m: f64,
    /// Obstacle avoidance safety margin in meters
    obstacle_safety_margin_m: f64,
}

impl SealedEventEngine {
    pub fn new() -> Self {
        Self {
            geofence_db: None,
            fired_events: Vec::new(),
            last_fired: HashMap::new(),
            dedup_window_secs: 60,
            obstacle_safety_margin_m: 5.0,
            geofence_max_distance_m: 500.0,
        }
    }

    pub fn with_geofence(mut self, db: GeofenceDatabase) -> Self {
        self.geofence_db = Some(db);
        self
    }

    /// Process a position update from MAVLink GLOBAL_POSITION_INT.
    /// lat/lon in degrees, alt in meters MSL.
    pub fn check_position(&mut self, lat: f64, lon: f64, alt_m: f64, timestamp: DateTime<Utc>) -> Vec<SealedEventRecord> {
        let alt_ft = alt_m * 3.28084; // Convert to feet MSL

        // Collect zone violation info without borrowing self mutably
        let mut triggers: Vec<(SealedEventType, String, serde_json::Value)> = Vec::new();

        if let Some(ref db) = self.geofence_db {
            let violated_zones = db.check_position(lat, lon, alt_ft);
            for zone in &violated_zones {
                if zone.zone_type == "restricted" || zone.airspace_class == "B" || zone.airspace_class == "C" {
                    triggers.push((
                        SealedEventType::AirspaceIncursion,
                        "mavlink_position".to_string(),
                        serde_json::json!({
                            "lat": lat, "lon": lon, "alt_m": alt_m,
                            "zone": zone.name, "class": zone.airspace_class
                        }),
                    ));
                }
                if zone.zone_type == "tfr" {
                    triggers.push((
                        SealedEventType::AirspaceIncursion,
                        "mavlink_position_tfr".to_string(),
                        serde_json::json!({
                            "lat": lat, "lon": lon, "alt_m": alt_m,
                            "zone": zone.name, "type": "TFR"
                        }),
                    ));
                }
            }

            if !db.is_in_permitted_area(lat, lon) && db.zones.iter().any(|z| z.zone_type == "permitted") {
                triggers.push((
                    SealedEventType::GeofenceViolation,
                    "geofence_boundary".to_string(),
                    serde_json::json!({ "lat": lat, "lon": lon, "alt_m": alt_m }),
                ));
            }
        }

        // Now fire events (requires &mut self)
        let mut events = Vec::new();
        for (event_type, source, context) in triggers {
            if let Some(event) = self.fire_event(event_type, timestamp, &source, context) {
                events.push(event);
            }
        }

        events
    }

    /// Process an obstacle distance reading.
    /// min_distance_m: closest obstacle distance in meters.
    pub fn check_obstacle(&mut self, min_distance_m: f64, timestamp: DateTime<Utc>) -> Option<SealedEventRecord> {
        if min_distance_m < self.obstacle_safety_margin_m {
            self.fire_event(
                SealedEventType::NearMiss,
                timestamp,
                "obstacle_avoidance",
                serde_json::json!({ "min_distance_m": min_distance_m, "safety_margin_m": self.obstacle_safety_margin_m }),
            )
        } else {
            None
        }
    }

    /// Process an emergency condition (low battery, GPS loss, link loss, etc.).
    pub fn trigger_emergency_landing(&mut self, reason: &str, timestamp: DateTime<Utc>) -> Option<SealedEventRecord> {
        self.fire_event(
            SealedEventType::EmergencyLanding,
            timestamp,
            "failsafe",
            serde_json::json!({ "reason": reason }),
        )
    }

    /// Process a payload anomaly (undeclared process, network connection, etc.).
    pub fn trigger_payload_anomaly(&mut self, details: &str, timestamp: DateTime<Utc>) -> Option<SealedEventRecord> {
        self.fire_event(
            SealedEventType::PayloadAnomaly,
            timestamp,
            "anomaly_detector",
            serde_json::json!({ "details": details }),
        )
    }

    /// Check if a data item at the given timestamp is covered by any sealed event preservation.
    pub fn is_sealed(&self, timestamp: DateTime<Utc>, _category: &DataCategory) -> bool {
        self.fired_events.iter().any(|event| {
            event.preservation_scope.time_range.contains(timestamp)
        })
    }

    /// Get all fired sealed events.
    pub fn fired_events(&self) -> &[SealedEventRecord] {
        &self.fired_events
    }

    /// Get count of fired events.
    pub fn event_count(&self) -> usize {
        self.fired_events.len()
    }

    // ─── Internal ───────────────────────────────────────────────────────

    fn fire_event(
        &mut self,
        event_type: SealedEventType,
        trigger_timestamp: DateTime<Utc>,
        source: &str,
        context: serde_json::Value,
    ) -> Option<SealedEventRecord> {
        let now = Utc::now();

        // Deduplication: don't fire same event type within window
        if let Some(last) = self.last_fired.get(&event_type) {
            if (now - *last).num_seconds() < self.dedup_window_secs {
                return None;
            }
        }

        let scope = Self::preservation_scope_for(event_type, trigger_timestamp);

        let record = SealedEventRecord {
            id: Uuid::new_v4().to_string(),
            event_type,
            trigger_timestamp,
            detection_timestamp: now,
            trigger_source: source.to_string(),
            preservation_scope: scope,
            context,
        };

        info!("SEALED EVENT FIRED: {} at {}", event_type, trigger_timestamp);
        self.last_fired.insert(event_type, now);
        self.fired_events.push(record.clone());

        Some(record)
    }

    /// Determine preservation scope for each sealed event type.
    /// From paper Section 6.1 table.
    fn preservation_scope_for(event_type: SealedEventType, trigger: DateTime<Utc>) -> PreservationScope {
        match event_type {
            SealedEventType::AirspaceIncursion => PreservationScope {
                time_range: TimeRange::around(trigger, Duration::seconds(30), Duration::seconds(30)),
                data_categories: vec![DataCategory::FlightTelemetry],
                stakeholders: vec!["all".to_string()],
                retention_days: 365,
            },
            SealedEventType::NearMiss => PreservationScope {
                time_range: TimeRange::around(trigger, Duration::seconds(10), Duration::seconds(10)),
                data_categories: vec![
                    DataCategory::FlightTelemetry,
                    DataCategory::EoImagery,
                    DataCategory::ThermalImagery,
                    DataCategory::LidarPointCloud,
                ],
                stakeholders: vec!["operator".to_string(), "regulator".to_string()],
                retention_days: 365,
            },
            SealedEventType::EmergencyLanding => PreservationScope {
                time_range: TimeRange::new(
                    trigger - Duration::seconds(60),
                    trigger + Duration::seconds(300), // Through landing completion
                ),
                data_categories: vec![DataCategory::FlightTelemetry, DataCategory::SystemStatus],
                stakeholders: vec!["regulator".to_string()],
                retention_days: 365,
            },
            SealedEventType::GeofenceViolation => PreservationScope {
                time_range: TimeRange::around(trigger, Duration::seconds(5), Duration::seconds(5)),
                data_categories: vec![DataCategory::FlightTelemetry],
                stakeholders: vec!["regulator".to_string()],
                retention_days: 90,
            },
            SealedEventType::PayloadAnomaly => PreservationScope {
                time_range: TimeRange::around(trigger, Duration::seconds(30), Duration::seconds(30)),
                data_categories: vec![
                    DataCategory::FlightTelemetry,
                    DataCategory::AnomalyLog,
                    DataCategory::EoImagery,
                ],
                stakeholders: vec!["operator".to_string()],
                retention_days: 90,
            },
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_geojson() -> &'static str {
        r#"{
            "type": "FeatureCollection",
            "features": [
                {
                    "type": "Feature",
                    "properties": {
                        "name": "Permitted Flight Area",
                        "airspace_class": "G",
                        "zone_type": "permitted",
                        "floor_ft_msl": 0,
                        "ceiling_ft_msl": 400
                    },
                    "geometry": {
                        "type": "Polygon",
                        "coordinates": [[
                            [8.540, 47.393],
                            [8.555, 47.393],
                            [8.555, 47.403],
                            [8.540, 47.403],
                            [8.540, 47.393]
                        ]]
                    }
                },
                {
                    "type": "Feature",
                    "properties": {
                        "name": "Restricted Zone B",
                        "airspace_class": "B",
                        "zone_type": "restricted",
                        "floor_ft_msl": 0,
                        "ceiling_ft_msl": 10000
                    },
                    "geometry": {
                        "type": "Polygon",
                        "coordinates": [[
                            [8.555, 47.400],
                            [8.565, 47.400],
                            [8.565, 47.410],
                            [8.555, 47.410],
                            [8.555, 47.400]
                        ]]
                    }
                }
            ]
        }"#
    }

    #[test]
    fn load_geofence_database() {
        let db = GeofenceDatabase::from_geojson(test_geojson()).unwrap();
        assert_eq!(db.zone_count(), 2);
    }

    #[test]
    fn position_in_permitted_area() {
        let db = GeofenceDatabase::from_geojson(test_geojson()).unwrap();
        // Center of permitted area
        assert!(db.is_in_permitted_area(47.398, 8.547));
        // Outside all zones
        assert!(!db.is_in_permitted_area(47.500, 8.600));
    }

    #[test]
    fn position_in_restricted_zone() {
        let db = GeofenceDatabase::from_geojson(test_geojson()).unwrap();
        let zones = db.check_position(47.405, 8.560, 100.0);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].name, "Restricted Zone B");
    }

    #[test]
    fn position_not_in_restricted() {
        let db = GeofenceDatabase::from_geojson(test_geojson()).unwrap();
        let zones = db.check_position(47.398, 8.547, 100.0);
        assert!(zones.is_empty());
    }

    #[test]
    fn altitude_filtering() {
        let db = GeofenceDatabase::from_geojson(test_geojson()).unwrap();
        // Above ceiling of restricted zone (10000 ft)
        let zones = db.check_position(47.405, 8.560, 11000.0);
        assert!(zones.is_empty());
    }

    #[test]
    fn airspace_incursion_fires() {
        let db = GeofenceDatabase::from_geojson(test_geojson()).unwrap();
        let mut engine = SealedEventEngine::new().with_geofence(db);

        // Fly into restricted zone (also outside permitted area, so may fire geofence violation too)
        let events = engine.check_position(47.405, 8.560, 30.0, Utc::now());
        assert!(!events.is_empty());
        assert!(events.iter().any(|e| e.event_type == SealedEventType::AirspaceIncursion));
    }

    #[test]
    fn geofence_violation_fires() {
        let db = GeofenceDatabase::from_geojson(test_geojson()).unwrap();
        let mut engine = SealedEventEngine::new().with_geofence(db);

        // Fly outside permitted area (but not into restricted)
        let events = engine.check_position(47.410, 8.530, 30.0, Utc::now());
        assert!(events.iter().any(|e| e.event_type == SealedEventType::GeofenceViolation));
    }

    #[test]
    fn no_event_in_permitted_area() {
        let db = GeofenceDatabase::from_geojson(test_geojson()).unwrap();
        let mut engine = SealedEventEngine::new().with_geofence(db);

        let events = engine.check_position(47.398, 8.547, 30.0, Utc::now());
        assert!(events.is_empty());
    }

    #[test]
    fn deduplication() {
        let mut engine = SealedEventEngine::new();

        // Fire emergency landing twice quickly
        let first = engine.trigger_emergency_landing("low_battery", Utc::now());
        assert!(first.is_some());

        let second = engine.trigger_emergency_landing("low_battery", Utc::now());
        assert!(second.is_none(), "Should be deduplicated within 60s window");

        assert_eq!(engine.event_count(), 1);
    }

    #[test]
    fn near_miss_fires() {
        let mut engine = SealedEventEngine::new();
        let event = engine.check_obstacle(2.0, Utc::now());
        assert!(event.is_some());
        assert_eq!(event.unwrap().event_type, SealedEventType::NearMiss);
    }

    #[test]
    fn near_miss_does_not_fire_above_margin() {
        let mut engine = SealedEventEngine::new();
        let event = engine.check_obstacle(10.0, Utc::now());
        assert!(event.is_none());
    }

    #[test]
    fn payload_anomaly_fires() {
        let mut engine = SealedEventEngine::new();
        let event = engine.trigger_payload_anomaly("undeclared process reading camera", Utc::now());
        assert!(event.is_some());
        assert_eq!(event.unwrap().event_type, SealedEventType::PayloadAnomaly);
    }

    #[test]
    fn is_sealed_checks_time_range() {
        let mut engine = SealedEventEngine::new();
        let now = Utc::now();
        engine.trigger_emergency_landing("test", now);

        // Within the preservation window (T-60s to T+300s)
        assert!(engine.is_sealed(now, &DataCategory::FlightTelemetry));
        assert!(engine.is_sealed(now - Duration::seconds(30), &DataCategory::FlightTelemetry));

        // Outside the window
        assert!(!engine.is_sealed(now - Duration::seconds(120), &DataCategory::FlightTelemetry));
    }

    #[test]
    fn preservation_scope_correct_per_type() {
        let now = Utc::now();

        let scope = SealedEventEngine::preservation_scope_for(SealedEventType::AirspaceIncursion, now);
        assert_eq!(scope.retention_days, 365);
        assert!(scope.stakeholders.contains(&"all".to_string()));

        let scope = SealedEventEngine::preservation_scope_for(SealedEventType::GeofenceViolation, now);
        assert_eq!(scope.retention_days, 90);
        assert!(scope.stakeholders.contains(&"regulator".to_string()));
    }
}
