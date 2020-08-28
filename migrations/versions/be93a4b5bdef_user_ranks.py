"""user ranks

Revision ID: be93a4b5bdef
Revises: e2c0d9b6bd7e
Create Date: 2020-08-28 12:14:16.965113

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'be93a4b5bdef'
down_revision = 'e2c0d9b6bd7e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('rank',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=True),
    sa.Column('label', sa.String(length=128), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('account__rank',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('rank_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['rank_id'], ['rank.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['account.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'rank_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('account__rank')
    op.drop_table('rank')
    # ### end Alembic commands ###
