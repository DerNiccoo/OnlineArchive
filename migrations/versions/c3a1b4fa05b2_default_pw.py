"""default pw

Revision ID: c3a1b4fa05b2
Revises: cbfef8e9f9b4
Create Date: 2020-08-17 18:05:39.199738

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3a1b4fa05b2'
down_revision = 'cbfef8e9f9b4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('account', sa.Column('default_pw', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('account', 'default_pw')
    # ### end Alembic commands ###
