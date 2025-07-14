class guarded
{
public:
	std::uintptr_t guard_address = 0;

	bool is_guarded( const std::uintptr_t& address ) const noexcept
	{
		return ( address & 0xFFFFFFF000000000 ) == 0x8000000000 or ( address & 0xFFFFFFF000000000 ) == 0x10000000000;
	}

	std::uintptr_t valid_ptr( const std::uintptr_t& address ) const noexcept
	{
		return this->is_guarded( address ) ? guard_address + ( address & 0xFFFFFF ) : address;
	}

	bool is_kernal( const std::uintptr_t& address ) const noexcept
	{
		return ( address & 0xFFF0000000000000 ) == 0xFFF0000000000000;
	}

	std::uintptr_t read_guarded( const std::uintptr_t& address ) const
	{
		std::uintptr_t buffer = 0;
		const int pid = this->is_kernal( address ) ? 4 : process_info.pid;

		constexpr auto vmdll_flags = VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING | VMMDLL_FLAG_NOCACHEPUT | VMMDLL_FLAG_NOPAGING_IO;
		VMMDLL_MemReadEx(
			request.vmm_handle, pid, static_cast< ULONG64 >( address ), reinterpret_cast< PBYTE >( &buffer ), sizeof( buffer ), NULL, vmdll_flags
		);

		return this->valid_ptr( buffer );
	}

	ULONG64 find_guarded_region( )
	{
		PVMMDLL_MAP_POOL map_pool;
		VMMDLL_Map_GetPool( request.vmm_handle, &map_pool, 0 );

		for ( std::size_t i = 0; i < map_pool->cMap; ++i )
		{
			PVMMDLL_MAP_POOLENTRY pool_entry = &map_pool->pMap[ i ];

			if ( pool_entry->cb == 0x200000 and std::memcmp( pool_entry->szTag, "ConT", 4 ) == 0 )
			{
				this->guard_address = pool_entry->va;
				VMMDLL_MemFree( map_pool );
				return this->guard_address;
			}
		}

		VMMDLL_MemFree( map_pool );
		return 0;
	}
};
