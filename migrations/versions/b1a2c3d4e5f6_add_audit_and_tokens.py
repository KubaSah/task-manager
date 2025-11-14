"""
add audit and tokens tables

Revision ID: b1a2c3d4e5f6
Revises: 9f1c2a4b7d10
Create Date: 2025-11-13
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b1a2c3d4e5f6'
down_revision = '9f1c2a4b7d10'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'api_tokens',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(length=120)),
        sa.Column('token_hash', sa.String(length=64), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime()),
        sa.Column('revoked', sa.Boolean(), nullable=False, server_default=sa.sql.expression.false()),
    )
    op.create_index('ix_api_token_user', 'api_tokens', ['user_id'])
    op.create_index('ix_api_token_hash', 'api_tokens', ['token_hash'])

    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('actor_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL')),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('entity_type', sa.String(length=50), nullable=False),
        sa.Column('entity_id', sa.Integer()),
        sa.Column('project_id', sa.Integer(), sa.ForeignKey('projects.id', ondelete='SET NULL')),
        sa.Column('meta', sa.Text()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

def downgrade():
    op.drop_table('audit_logs')
    op.drop_index('ix_api_token_hash', table_name='api_tokens')
    op.drop_index('ix_api_token_user', table_name='api_tokens')
    op.drop_table('api_tokens')
