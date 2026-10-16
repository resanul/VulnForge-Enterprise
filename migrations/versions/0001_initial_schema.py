"""Initial schema migration for VulnForge Enterprise

Revision ID: 0001_initial
Revises: 
Create Date: 2026-10-16 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '0001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=128), nullable=False),
        sa.Column('hashed_password', sa.String(length=256), nullable=False),
        sa.Column('full_name', sa.String(length=128), nullable=True),
        sa.Column('role', sa.String(length=32), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('mfa_enabled', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.Column('last_login', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Approved Scopes table
    op.create_table(
        'approved_scopes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('target_pattern', sa.String(length=256), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=True),
        sa.Column('approved_by', sa.String(length=64), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_approved_scopes_id'), 'approved_scopes', ['id'], unique=False)

    # Assets table
    op.create_table(
        'assets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('target_type', sa.String(length=32), nullable=True),
        sa.Column('target_value', sa.String(length=256), nullable=False),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('criticality', sa.String(length=32), nullable=True),
        sa.Column('environment', sa.String(length=32), nullable=True),
        sa.Column('network_zone', sa.String(length=64), nullable=True),
        sa.Column('owner', sa.String(length=128), nullable=True),
        sa.Column('tags', sa.String(length=256), nullable=True),
        sa.Column('authorized', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.Column('updated_at', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_assets_id'), 'assets', ['id'], unique=False)
    op.create_index(op.f('ix_assets_target_value'), 'assets', ['target_value'], unique=False)

    # Credentials table
    op.create_table(
        'credentials',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('cred_type', sa.String(length=32), nullable=False),
        sa.Column('username', sa.String(length=128), nullable=True),
        sa.Column('encrypted_secret', sa.Text(), nullable=False),
        sa.Column('encrypted_passphrase', sa.Text(), nullable=True),
        sa.Column('domain', sa.String(length=128), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('extra_data', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.Column('updated_at', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_credentials_id'), 'credentials', ['id'], unique=False)

    # Scan Profiles table
    op.create_table(
        'scan_profiles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('description', sa.String(length=256), nullable=True),
        sa.Column('categories', sa.Text(), nullable=True),
        sa.Column('safe_mode', sa.Boolean(), nullable=True),
        sa.Column('ports_mode', sa.String(length=32), nullable=True),
        sa.Column('custom_ports', sa.String(length=256), nullable=True),
        sa.Column('credential_id', sa.Integer(), nullable=True),
        sa.Column('timeout_seconds', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['credential_id'], ['credentials.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_profiles_id'), 'scan_profiles', ['id'], unique=False)

    # Scan Jobs table
    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=128), nullable=False),
        sa.Column('target', sa.String(length=256), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('profile_id', sa.Integer(), nullable=True),
        sa.Column('credential_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.Integer(), nullable=True),
        sa.Column('finished_at', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('log_output', sa.Text(), nullable=True),
        sa.Column('summary_stats', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['credential_id'], ['credentials.id'], ),
        sa.ForeignKeyConstraint(['profile_id'], ['scan_profiles.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_jobs_id'), 'scan_jobs', ['id'], unique=False)

    # Findings table
    op.create_table(
        'findings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('asset_id', sa.Integer(), nullable=False),
        sa.Column('job_id', sa.Integer(), nullable=True),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=128), nullable=True),
        sa.Column('cve', sa.String(length=64), nullable=True),
        sa.Column('cwe', sa.String(length=64), nullable=True),
        sa.Column('confidence', sa.String(length=32), nullable=True),
        sa.Column('detection_method', sa.String(length=64), nullable=True),
        sa.Column('is_credentialed', sa.Boolean(), nullable=True),
        sa.Column('affected_component', sa.String(length=128), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=16), nullable=True),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=True),
        sa.Column('first_seen', sa.Integer(), nullable=True),
        sa.Column('last_seen', sa.Integer(), nullable=True),
        sa.Column('suppression_reason', sa.String(length=256), nullable=True),
        sa.Column('suppression_expires_at', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_id'), 'findings', ['id'], unique=False)
    op.create_index(op.f('ix_findings_asset_id'), 'findings', ['asset_id'], unique=False)
    op.create_index(op.f('ix_findings_fingerprint'), 'findings', ['fingerprint'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_cve'), 'findings', ['cve'], unique=False)
    op.create_index('idx_asset_fingerprint', 'findings', ['asset_id', 'fingerprint'], unique=True)

    # Compliance Results table
    op.create_table(
        'compliance_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('job_id', sa.Integer(), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('framework', sa.String(length=64), nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=256), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=True),
        sa.Column('severity', sa.String(length=32), nullable=True),
        sa.Column('observed_value', sa.Text(), nullable=True),
        sa.Column('expected_value', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
        sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_compliance_results_id'), 'compliance_results', ['id'], unique=False)

    # Remediation Tasks table
    op.create_table(
        'remediation_tasks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=256), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=True),
        sa.Column('priority', sa.String(length=32), nullable=True),
        sa.Column('assignee', sa.String(length=128), nullable=True),
        sa.Column('due_date', sa.String(length=32), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_remediation_tasks_id'), 'remediation_tasks', ['id'], unique=False)

def downgrade() -> None:
    op.drop_table('remediation_tasks')
    op.drop_table('compliance_results')
    op.drop_table('findings')
    op.drop_table('scan_jobs')
    op.drop_table('scan_profiles')
    op.drop_table('credentials')
    op.drop_table('assets')
    op.drop_table('approved_scopes')
    op.drop_table('users')
