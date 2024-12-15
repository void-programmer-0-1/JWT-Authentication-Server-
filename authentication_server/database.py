from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
from enum import Enum

DATABASE_URL = "sqlite+aiosqlite:///./game.db"
engine = create_async_engine(DATABASE_URL, connect_args={"check_same_thread": False})
session = async_sessionmaker(engine)
Base = declarative_base()


class DBFlags(Enum):
    SUCCESS: int = 1
    FAILED: int = 0
    UNIQUE_CONSTRAIN_ERR: int = 2


class User(Base):
    __tablename__ = "User"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, nullable=False, unique=True)
    email = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_engine():
    await engine.dispose()


async def get_db():
    db = session()
    try:
        yield db
    finally:
        await db.close()


class UserSchemaUtils:

    def handle_integrity_error(self, error_msg) -> tuple[str, DBFlags]:
        field = ""
        
        # handling the unique constraint
        if "UNIQUE constraint failed" in error_msg:
            field = error_msg.split(": ")[1].split(".")[1]
            return f"{field.lower()} provided by the user already exists", DBFlags.UNIQUE_CONSTRAIN_ERR

        else:
            return "Database Connection Failed", DBFlags.FAILED

    async def create_user(
            self, 
            db: AsyncSession, 
            username: str, 
            email: str, 
            password: str
    ) -> tuple[str, DBFlags]:
        try:
            user = User(username=username, email=email, password=password)
            db.add(user)
            await db.commit()
            return "User Registered Successfully", DBFlags.SUCCESS

        except IntegrityError as err:
            await db.rollback()
            error_msg = str(err.orig)
            return self.handle_integrity_error(error_msg)

        except Exception as err:
            print(f"Error occured while creating user for {username} err:: {str(err)}")
            return f"Error occured while creating user for {username}", DBFlags.FAILED


    async def get_user_with_username(
            self,
            db: AsyncSession,
            username: str
    ) -> tuple[User, str, DBFlags]:
        try:
            stmt = select(User).where(User.username == username)
            result = await db.execute(stmt)
            user = result.scalars().first()
            if not user:
                return None, "User not found", DBFlags.FAILED
            return user, "success", DBFlags.SUCCESS
        except Exception as err:
            print(f"Error occured while getting the user:: {str(err)}")
            return None, "Internal Server Failure while fetching the user", DBFlags.FAILED    


    async def get_all_users(
        self,
        db: AsyncSession
    ) -> tuple[list[dict], str, DBFlags]:
        try:
            # Query to fetch all users
            stmt = select(User)
            result = await db.execute(stmt)
            users = result.scalars().all()

            if not users:
                return [], "No users found", DBFlags.SUCCESS

            # Convert user objects to dictionaries
            users_data = [
                {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                }
                for user in users
            ]

            return users_data, "success", DBFlags.SUCCESS

        except Exception as err:
            print(f"Unexpected error occurred while fetching users: {str(err)}")
            return [], "Unexpected Internal Server Failure", DBFlags.FAILED
        

    async def get_user_with_id(self, db: AsyncSession, user_id: int) -> tuple[User, str, DBFlags]:
        try:
            stmt = select(User).where(User.id == user_id)
            result = await db.execute(stmt)
            user = result.scalars().first()
            
            if not user:
                return None, "User not found", DBFlags.FAILED
            
            return user, "success", DBFlags.SUCCESS
        
        except Exception as err:
            print(f"Error occurred while fetching user by ID {user_id}: {str(err)}")
            return None, "Internal Server Failure while fetching the user", DBFlags.FAILED


    async def update_user(
        self,
        db: AsyncSession,
        user_id: int,
        username: str = None,
        email: str = None,
        password: str = None
    ) -> tuple[str, DBFlags]:
        try:
            user, response, db_conn_status = await self.get_user_with_id(db, user_id)
            if not user:
                return "User not found", DBFlags.FAILED

            if username:
                user.username = username
            if email:
                user.email = email
            if password:
                user.password = password

            db.add(user)
            await db.commit()

            return "User updated successfully", DBFlags.SUCCESS

        except Exception as err:
            await db.rollback()
            print(f"Error occurred while updating user {user_id}: {str(err)}")
            return "Error occurred while updating user", DBFlags.FAILED
        

    async def delete_user(self, db: AsyncSession, user_id: int) -> tuple[str, DBFlags]:
        try:
            user, reponse, db_conn_flag = await self.get_user_with_id(db, user_id)
            if not user:
                return "User not found", DBFlags.FAILED

            await db.delete(user)
            await db.commit()

            return "User deleted successfully", DBFlags.SUCCESS

        except Exception as err:
            await db.rollback()
            print(f"Error occurred while deleting user {user_id}: {str(err)}")
            return "Error occurred while deleting user", DBFlags.FAILED



