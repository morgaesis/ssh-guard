use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: String,
    pub permissions: Vec<Permission>,
    pub max_requests_per_minute: Option<u32>,
    pub allowed_models: Vec<String>,
    pub max_tokens: Option<u32>,
    pub allowed_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Permission {
    UseModel(String),
    Stream,
    Cache,
    CreateValidationRules,
    ViewMetrics,
    ManageRoles,
    ManageUsers,
    ViewAuditLogs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub roles: Vec<String>,
    pub api_key: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub description: String,
    pub roles: Vec<String>,
    pub resources: Vec<String>,
    pub actions: Vec<String>,
    pub conditions: Option<PolicyCondition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub time_of_day: Option<TimeRange>,
    pub day_of_week: Option<Vec<u8>>,
    pub ip_ranges: Option<Vec<String>>,
    pub custom_attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start_hour: u8,
    pub end_hour: u8,
}

pub struct RbacManager {
    roles: Arc<RwLock<HashMap<String, Role>>>,
    users: Arc<RwLock<HashMap<String, User>>>,
    policies: Arc<RwLock<Vec<Policy>>>,
}

impl RbacManager {
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn add_role(&self, role: Role) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);
        Ok(())
    }

    pub async fn add_user(&self, user: User) -> Result<()> {
        // Validate that all roles exist
        let roles = self.roles.read().await;
        for role_name in &user.roles {
            if !roles.contains_key(role_name) {
                anyhow::bail!("Role {} does not exist", role_name);
            }
        }

        let mut users = self.users.write().await;
        users.insert(user.id.clone(), user);
        Ok(())
    }

    pub async fn add_policy(&self, policy: Policy) -> Result<()> {
        // Validate that all roles exist
        let roles = self.roles.read().await;
        for role_name in &policy.roles {
            if !roles.contains_key(role_name) {
                anyhow::bail!("Role {} does not exist", role_name);
            }
        }

        let mut policies = self.policies.write().await;
        policies.push(policy);
        Ok(())
    }

    pub async fn check_permission(
        &self,
        user_id: &str,
        resource: &str,
        action: &str,
    ) -> Result<bool> {
        let users = self.users.read().await;
        let user = users
            .get(user_id)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let roles = self.roles.read().await;
        let policies = self.policies.read().await;

        // Check each policy that applies to the user's roles
        for policy in policies.iter() {
            if !policy.roles.iter().any(|r| user.roles.contains(r)) {
                continue;
            }

            if !policy.resources.iter().any(|r| resource_matches(r, resource)) {
                continue;
            }

            if !policy.actions.iter().any(|a| action_matches(a, action)) {
                continue;
            }

            // Check conditions if present
            if let Some(conditions) = &policy.conditions {
                if !evaluate_conditions(conditions)? {
                    continue;
                }
            }

            // Check role-specific permissions
            for role_name in &user.roles {
                if let Some(role) = roles.get(role_name) {
                    // Check if role has required permission
                    match action {
                        "use_model" => {
                            if !role
                                .allowed_models
                                .iter()
                                .any(|m| resource_matches(m, resource))
                            {
                                continue;
                            }
                        }
                        _ => {
                            let permission = action_to_permission(action, resource);
                            if !role.permissions.contains(&permission) {
                                continue;
                            }
                        }
                    }

                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub async fn get_user_permissions(&self, user_id: &str) -> Result<Vec<Permission>> {
        let users = self.users.read().await;
        let user = users
            .get(user_id)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        let roles = self.roles.read().await;
        let mut permissions = Vec::new();

        for role_name in &user.roles {
            if let Some(role) = roles.get(role_name) {
                permissions.extend(role.permissions.clone());
            }
        }

        // Remove duplicates
        permissions.sort_unstable();
        permissions.dedup();

        Ok(permissions)
    }

    pub async fn validate_api_key(&self, api_key: &str) -> Result<String> {
        let users = self.users.read().await;
        for (user_id, user) in users.iter() {
            if user.api_key == api_key {
                return Ok(user_id.clone());
            }
        }
        anyhow::bail!("Invalid API key")
    }
}

fn resource_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Support simple wildcards
    let pattern = pattern.replace("*", ".*");
    let re = regex::Regex::new(&pattern).unwrap_or_else(|_| regex::Regex::new("^$").unwrap());
    re.is_match(resource)
}

fn action_matches(pattern: &str, action: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    pattern == action
}

fn action_to_permission(action: &str, resource: &str) -> Permission {
    match action {
        "use_model" => Permission::UseModel(resource.to_string()),
        "stream" => Permission::Stream,
        "cache" => Permission::Cache,
        "create_validation_rules" => Permission::CreateValidationRules,
        "view_metrics" => Permission::ViewMetrics,
        "manage_roles" => Permission::ManageRoles,
        "manage_users" => Permission::ManageUsers,
        "view_audit_logs" => Permission::ViewAuditLogs,
        _ => Permission::UseModel("*".to_string()), // Default to most restrictive
    }
}

fn evaluate_conditions(conditions: &PolicyCondition) -> Result<bool> {
    // Check time of day
    if let Some(time_range) = &conditions.time_of_day {
        let now = chrono::Local::now();
        let current_hour = now.hour() as u8;
        if current_hour < time_range.start_hour || current_hour >= time_range.end_hour {
            return Ok(false);
        }
    }

    // Check day of week
    if let Some(allowed_days) = &conditions.day_of_week {
        let now = chrono::Local::now();
        let current_day = now.weekday().num_days_from_monday() as u8;
        if !allowed_days.contains(&current_day) {
            return Ok(false);
        }
    }

    // Check IP ranges
    if let Some(ip_ranges) = &conditions.ip_ranges {
        // In a real implementation, this would check the client IP
        // For now, we'll just check if any ranges are specified
        if ip_ranges.is_empty() {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_rbac() -> RbacManager {
        let rbac = RbacManager::new();

        // Add test roles
        let admin_role = Role {
            name: "admin".to_string(),
            description: "Administrator".to_string(),
            permissions: vec![
                Permission::ManageRoles,
                Permission::ManageUsers,
                Permission::ViewMetrics,
                Permission::ViewAuditLogs,
            ],
            max_requests_per_minute: None,
            allowed_models: vec!["*".to_string()],
            max_tokens: None,
            allowed_features: vec!["*".to_string()],
        };

        let user_role = Role {
            name: "user".to_string(),
            description: "Basic user".to_string(),
            permissions: vec![Permission::UseModel("gpt-3.5-turbo".to_string())],
            max_requests_per_minute: Some(60),
            allowed_models: vec!["gpt-3.5-turbo".to_string()],
            max_tokens: Some(4000),
            allowed_features: vec!["stream".to_string()],
        };

        rbac.add_role(admin_role).await.unwrap();
        rbac.add_role(user_role).await.unwrap();

        // Add test users
        let admin_user = User {
            id: "admin1".to_string(),
            roles: vec!["admin".to_string()],
            api_key: "admin-key".to_string(),
            metadata: HashMap::new(),
        };

        let basic_user = User {
            id: "user1".to_string(),
            roles: vec!["user".to_string()],
            api_key: "user-key".to_string(),
            metadata: HashMap::new(),
        };

        rbac.add_user(admin_user).await.unwrap();
        rbac.add_user(basic_user).await.unwrap();

        // Add test policies
        let admin_policy = Policy {
            name: "admin_access".to_string(),
            description: "Admin access policy".to_string(),
            roles: vec!["admin".to_string()],
            resources: vec!["*".to_string()],
            actions: vec!["*".to_string()],
            conditions: None,
        };

        let user_policy = Policy {
            name: "user_access".to_string(),
            description: "User access policy".to_string(),
            roles: vec!["user".to_string()],
            resources: vec!["gpt-3.5-turbo".to_string()],
            actions: vec!["use_model", "stream"].to_string(),
            conditions: Some(PolicyCondition {
                time_of_day: Some(TimeRange {
                    start_hour: 9,
                    end_hour: 17,
                }),
                day_of_week: Some(vec![1, 2, 3, 4, 5]),
                ip_ranges: None,
                custom_attributes: None,
            }),
        };

        rbac.add_policy(admin_policy).await.unwrap();
        rbac.add_policy(user_policy).await.unwrap();

        rbac
    }

    #[tokio::test]
    async fn test_permission_checking() {
        let rbac = setup_test_rbac().await;

        // Test admin permissions
        assert!(rbac
            .check_permission("admin1", "gpt-4", "use_model")
            .await
            .unwrap());
        assert!(rbac
            .check_permission("admin1", "users", "manage_users")
            .await
            .unwrap());

        // Test user permissions
        assert!(rbac
            .check_permission("user1", "gpt-3.5-turbo", "use_model")
            .await
            .unwrap());
        assert!(!rbac
            .check_permission("user1", "gpt-4", "use_model")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_api_key_validation() {
        let rbac = setup_test_rbac().await;

        assert_eq!(
            rbac.validate_api_key("admin-key").await.unwrap(),
            "admin1".to_string()
        );
        assert!(rbac.validate_api_key("invalid-key").await.is_err());
    }

    #[tokio::test]
    async fn test_user_permissions() {
        let rbac = setup_test_rbac().await;

        let admin_permissions = rbac.get_user_permissions("admin1").await.unwrap();
        assert!(admin_permissions.contains(&Permission::ManageUsers));

        let user_permissions = rbac.get_user_permissions("user1").await.unwrap();
        assert!(user_permissions.contains(&Permission::UseModel("gpt-3.5-turbo".to_string())));
        assert!(!user_permissions.contains(&Permission::ManageUsers));
    }
}