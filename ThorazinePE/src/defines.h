#ifndef PE_DEFINES_H
#define PE_DEFINES_H

#if defined( _WIN64 ) && defined( __cplusplus )
	#define WINDOWS_x86_64 1
		#include <cstdint>
		#include <type_traits>
		#include <limits>
		#include <ranges>
		#include <string>
		#include <algorithm>
		#include <functional>
		#include <span>
		#include <string_view>

		#include "fnv1a.h"
	#define WIN32_LEAN_AND_MEAN
	#define NO_MIN_MAX
		#include <windows.h>
#else 
	#error No platform specified
#endif

#if defined( __clang__ )
	#define COMPILER_CLANG 1
#else
	#define COMPILER_CLANG 0
#endif

#if defined( _MSC_VER ) && !COMPILER_CLANG
	#define COMPILER_MSVC 1
#else
	#define COMPILER_MSVC 0
#endif

#if !defined( COMPILER_MSVC ) && !defined( COMPILER_CLANG )
	#error No available compiler specified
#endif

#define NT_CALL __stdcall

#define library( str ) ::thorazine::pe::module_t{ FNV( #str ) }
#define import_symbol( m, e ) ::thorazine::pe::exported_symbol( FNV( #e ), FNV( #m ) ).address( )
#define import_symbol_crtless( m, e ) ::thorazine::pe::exported_symbol( FNV( #e ), FNV( #m ), true ).address( )
#define import( m, e ) import_symbol( m, e ).execute

namespace thorazine
{
	namespace pe
	{ 
		namespace concepts
		{
			template < typename Ty >
			concept pointer = std::is_pointer_v<Ty>;
		}

		// define everything
		using handle    = void*;
		using nt_status = long;

		class  address_t;
		class  exported_symbol_t;
		struct list_entry_t;
		struct peb_ldr_data_t;
		struct unicode_string_t;
		struct string_t;
		struct current_dir_t;
		struct rtl_drive_letter_curdir_t;
		struct rtl_user_process_parameters_t;
		struct api_set_namespace_t;
		struct rtl_bitmap_t;
		struct system_time_t;
		struct silo_user_shared_data_t;
		struct ldr_table_entry_t;
		struct peb_t;
		struct nt_headers_t;

		__forceinline constexpr bool   nt_success		( const nt_status s );
		__forceinline constexpr handle current_process	( );
		__forceinline constexpr handle current_thread	( );

		__forceinline peb_t*      current_peb ( );
		__forceinline std::string utf8_encode ( const std::wstring& wstr );

		template < typename T = std::uint32_t >
		__forceinline T rva_2_offset( std::uint32_t rva, nt_headers_t* nt_headers = nullptr, bool mapped_in_memory = false );

		template <typename T, typename FieldT>
		__forceinline constexpr T* containing_record( FieldT* address, FieldT T::* field )
		{
			auto offset = reinterpret_cast< std::uintptr_t >( &( reinterpret_cast< T* >( 0 )->*field ) );
			return reinterpret_cast< T* >( reinterpret_cast< std::uintptr_t >( address ) - offset );
		}

		__forceinline auto exported_symbol( std::uint64_t export_name, std::uint64_t module_name = 0, bool crt_less = false );

		enum class e_nt_product_t : std::int32_t
		{
			nt_product_win_nt = 1,
			nt_product_lan_man_nt,
			nt_product_server
		};

		enum class e_subsystem_id : std::uint16_t
		{
			unknown = 0x0000,         // Unknown subsystem.
			native = 0x0001,          // Image doesn't require a subsystem.
			windows_gui = 0x0002,     // Image runs in the Windows GUI subsystem.
			windows_cui = 0x0003,     // Image runs in the Windows character subsystem
			os2_cui = 0x0005,         // image runs in the OS/2 character subsystem.
			posix_cui = 0x0007,       // image runs in the Posix character subsystem.
			native_windows = 0x0008,  // image is a native Win9x driver.
			windows_ce_gui = 0x0009,  // Image runs in the Windows CE subsystem.
			efi_application = 0x000A,
			efi_boot_service_driver = 0x000B,
			efi_runtime_driver = 0x000C,
			efi_rom = 0x000D,
			xbox = 0x000E,
			windows_boot_application = 0x0010,
			xbox_code_catalog = 0x0011,
		};

		enum class e_section_inherit : DWORD
		{
			VIEW_SHARE = 1,
			VIEW_UNMAP = 2
		};

		enum class e_section_alloc_attributes : ULONG
		{
			SECTION_COMMIT = SEC_COMMIT,
			SECTION_IMAGE = SEC_IMAGE,
			SECTION_IMAGE_NO_EXECUTE = SEC_IMAGE_NO_EXECUTE,
			SECTION_LARGE_PAGES = SEC_LARGE_PAGES,
			SECTION_NO_CHANGE = 0x00400000,
			SECTION_RESERVE = SEC_RESERVE,
		};

		enum e_directory_id : std::uint8_t
		{
			directory_entry_export = 0,           // Export Directory
			directory_entry_import = 1,           // Import Directory
			directory_entry_resource = 2,         // Resource Directory
			directory_entry_exception = 3,        // Exception Directory
			directory_entry_security = 4,         // Security Directory
			directory_entry_basereloc = 5,        // Base Relocation Table
			directory_entry_debug = 6,            // Debug Directory
			directory_entry_copyright = 7,        // (X86 usage)
			directory_entry_architecture = 7,     // Architecture Specific Data
			directory_entry_globalptr = 8,        // RVA of GP
			directory_entry_tls = 9,              // TLS Directory
			directory_entry_load_config = 10,     // Load Configuration Directory
			directory_entry_bound_import = 11,    // Bound Import Directory in headers
			directory_entry_iat = 12,             // Import Address Table
			directory_entry_delay_import = 13,    // Delay Load Import Descriptors
			directory_entry_com_descriptor = 14,  // COM Runtime descriptor
			directory_reserved0 = 15,             // -
		};

		class address_t
		{
		public:

			using underlying_t = std::uintptr_t;

			constexpr address_t( ) = default;

			constexpr address_t( underlying_t address ) noexcept 
				: m_address( address ) 
			{ }

			constexpr address_t( concepts::pointer auto address ) noexcept
				: m_address( reinterpret_cast< underlying_t >( address ) )
			{ }

			address_t( const address_t& ) = default;
			address_t( address_t&& ) = default;
			address_t& operator=( const address_t& ) = default;
			address_t& operator=( address_t&& ) = default;
			~address_t( ) = default;

			template <typename Ty>
			__forceinline constexpr Ty as( ) const noexcept
			{
				if constexpr ( std::is_pointer_v<Ty> )
					return reinterpret_cast< Ty >( m_address );
				else
					return static_cast< Ty >( m_address );
			}

			template <typename Ty = address_t>
			__forceinline constexpr Ty offset( std::ptrdiff_t offset = 0 ) const noexcept
			{
				if constexpr ( std::is_pointer_v<Ty> )
					return m_address == 0u ? nullptr : reinterpret_cast< Ty >( m_address + offset );
				else
					return m_address == 0u ? static_cast< Ty >( *this ) : Ty{ m_address + offset };
			}

			template <typename Ty, typename... Args>
			[[nodiscard]] Ty execute( Args&&... args ) const noexcept
			{
				if ( m_address == 0 )
				{
					if constexpr ( std::is_pointer_v<Ty> )
						return nullptr;
					else
						return Ty{ };
				}

				using target_function_t = Ty( __stdcall* )( std::decay_t<Args>... );
				const auto target_function = reinterpret_cast< target_function_t >( m_address );

				return target_function( std::forward<Args>( args )... );
			}

			template <typename Ty = void, typename PointerTy = std::add_pointer_t<Ty>>
			__forceinline constexpr PointerTy ptr( std::ptrdiff_t offset = 0 ) const noexcept
			{
				return this->offset( offset ).as<PointerTy>( );
			}

			__forceinline constexpr underlying_t raw( ) const noexcept
			{
				return m_address;
			}

			template <typename Ty>
			[[nodiscard]] constexpr std::span<Ty> span( std::size_t count ) const noexcept
			{
				return { this->ptr<Ty>( ), count };
			}

			template < typename Ty = address_t >
			[[nodiscard]] __forceinline Ty resolve_rip( std::uint32_t rva, std::uint32_t rip ) const noexcept
			{
				auto resolved_rva = *reinterpret_cast< std::uint32_t* >( ptr< std::uint8_t >( ) + rva );
				auto resolved_rip =  reinterpret_cast< std::uint64_t >( ptr< std::uint8_t >( ) ) + rip;
				return reinterpret_cast< Ty* >( resolved_rva + resolved_rip );
			}

			__forceinline constexpr explicit operator std::uintptr_t( ) const noexcept
			{
				return m_address;
			}

			__forceinline constexpr explicit operator bool( ) const noexcept
			{
				return static_cast< bool >( m_address );
			}

			__forceinline constexpr auto operator==( const address_t& rhs ) const noexcept
			{
				return this->m_address == rhs.m_address;
			}

			__forceinline constexpr address_t operator+=( const address_t& rhs ) noexcept
			{
				m_address += rhs.m_address;
				return *this;
			}

			__forceinline constexpr address_t operator-=( const address_t& rhs ) noexcept
			{
				m_address -= rhs.m_address;
				return *this;
			}

			__forceinline constexpr address_t operator+( const address_t& rhs ) const noexcept
			{
				return { m_address + rhs.m_address };
			}

			__forceinline constexpr address_t operator-( const address_t& rhs ) const noexcept
			{
				return { m_address - rhs.m_address };
			}

			__forceinline constexpr address_t operator&( const address_t& other ) const noexcept
			{
				return { m_address & other.m_address };
			}

			__forceinline constexpr address_t operator|( const address_t& other ) const noexcept
			{
				return { m_address | other.m_address };
			}

			__forceinline constexpr address_t operator^( const address_t& other ) const noexcept
			{
				return { m_address ^ other.m_address };
			}

			__forceinline constexpr address_t operator<<( std::size_t shift ) const noexcept
			{
				return { m_address << shift };
			}

			__forceinline constexpr address_t operator>>( std::size_t shift ) const noexcept
			{
				return { m_address >> shift };
			}

		private:

			underlying_t m_address {  };

		};

		struct list_entry_t // same as _LDR_DATA_TABLE_ENTRY
		{
			list_entry_t* flink;
			list_entry_t* blink;

			template< class T >
			__forceinline constexpr T* as( ) noexcept
			{
				return reinterpret_cast< T* >( this );
			}
		};

		struct unicode_string_t
		{
			std::uint16_t length     { 0 };
			std::uint16_t max_length { 0 };
			wchar_t*      buffer     { nullptr };

			unicode_string_t( ) = default;

			explicit unicode_string_t( const std::wstring& str )
				noexcept
				: length{ static_cast< std::uint16_t >( ( str.size( ) + 1 ) * sizeof( wchar_t ) ) }, max_length{ length }, buffer{ const_cast< wchar_t* >( str.c_str( ) ) }
			{ }

			__forceinline std::wstring to_wstring( ) const noexcept
			{
				return std::wstring{ buffer };
			}

			__forceinline std::string to_string( ) const noexcept
			{
				return pe::utf8_encode( std::wstring{ buffer } );
			}

			__forceinline std::string to_sanitized_string( ) const noexcept
			{
				auto str = this->to_string( );

				std::transform
				(
					str.begin( ), str.end( ), str.begin( ),
					[ ]( unsigned char c ) { return std::tolower( c ); }
				);

				return str;
			}
		};

		struct ldr_table_entry_t
		{
			list_entry_t in_load_order_links;
			list_entry_t in_memory_order_links;
			union
			{
				list_entry_t in_initialization_order_links;
				list_entry_t in_progress_links;
			};
			address_t base_address;
			address_t entry_point;
			std::uint32_t size_image;
			unicode_string_t path;
			unicode_string_t name;
			union
			{
				std::uint8_t flag_group[ 4 ];
				std::uint32_t flags;
				struct
				{
					std::uint32_t packaged_binary : 1;
					std::uint32_t marked_for_removal : 1;
					std::uint32_t image_dll : 1;
					std::uint32_t load_notifications_sent : 1;
					std::uint32_t telemetry_entry_processed : 1;
					std::uint32_t static_import_processed : 1;
					std::uint32_t in_legacy_lists : 1;
					std::uint32_t in_indexes : 1;
					std::uint32_t shim_dll : 1;
					std::uint32_t in_exception_table : 1;
					std::uint32_t reserved_flags_1 : 2;
					std::uint32_t load_in_progress : 1;
					std::uint32_t load_config_processed : 1;
					std::uint32_t entry_point_processed : 1;
					std::uint32_t delay_load_protection_enabled : 1;
					std::uint32_t reserved_flags_3 : 2;
					std::uint32_t skip_thread_calls : 1;
					std::uint32_t process_attach_called : 1;
					std::uint32_t process_attach_failed : 1;
					std::uint32_t cor_validation_deferred : 1;
					std::uint32_t is_cor_image : 1;
					std::uint32_t skip_relocation : 1;
					std::uint32_t is_cor_il_only : 1;
					std::uint32_t is_chpe_image : 1;
					std::uint32_t reserved_flags_5 : 2;
					std::uint32_t redirected : 1;
					std::uint32_t reserved_flags_6 : 2;
					std::uint32_t compatibility_database_processed : 1;
				};
			};
			std::uint16_t obsolete_load_count;
			std::uint16_t tls_index;
			list_entry_t  hash_links;
			std::uint32_t time_date_stamp;
		};

		struct peb_ldr_data_t
		{
			std::uint32_t length;
			bool          initialized;
			handle        ss_handle;
			list_entry_t  in_load_order_links;
			list_entry_t  in_memory_order_links;
			list_entry_t  in_initialization_order_links;
			address_t     entry_in_progress;
			bool          shutdown_in_progress;
			handle        shutdown_thread_id;
		};

		struct string_t
		{
			std::uint16_t length     { 0 };
			std::uint16_t max_length { 0 };
			char*         buffer     { nullptr };

			__forceinline std::string to_string( ) const noexcept
			{
				return std::string{ buffer };
			}
		};

		struct current_dir_t
		{
			unicode_string_t dos_path;
			handle           h_handle;
		};

		struct rtl_drive_letter_curdir_t
		{
			std::uint16_t flags;
			std::uint16_t length;
			std::uint32_t time_stamp;
			string_t      dos_path;
		};

		struct rtl_user_process_parameters_t
		{
			std::uint32_t			maximum_length;
			std::uint32_t			length;
			std::uint32_t			flags;
			std::uint32_t			debug_flags;
			handle					console_handle;
			std::uint32_t			console_flags;
			handle					standard_input;
			handle					standard_output;
			handle					standard_error;
			current_dir_t			current_directory;
			unicode_string_t		dll_path;
			unicode_string_t		image_path_name;
			unicode_string_t		command_line;
			address_t				environment;
			std::uint32_t			starting_x;
			std::uint32_t			starting_y;
			std::uint32_t			count_x;
			std::uint32_t			count_y;
			std::uint32_t			count_chars_x;
			std::uint32_t			count_chars_y;
			std::uint32_t			fill_attribute;
			std::uint32_t			window_flags;
			std::uint32_t			show_window_flags;
			unicode_string_t		window_title;
			unicode_string_t		desktop_info;
			unicode_string_t		shell_info;
			unicode_string_t		runtime_data;
			rtl_drive_letter_curdir_t current_directories[ 32 ];
			std::uint32_t*			environment_size;
			std::uint32_t*			environment_version;
			address_t				package_dependency_data;
			std::uint32_t			process_group_id;
			std::uint32_t			loader_threads;
			unicode_string_t		redirection_dll_name; // REDSTONE4
			unicode_string_t		heap_partition_name;  // 19H1
			std::uint64_t*			default_threadpool_cpu_set_masks;
			std::uint32_t			default_threadpool_cpu_set_mask_count;
			std::uint32_t			default_threadpool_thread_maximum;
			std::uint32_t			heap_memory_type_mask; // WIN11
		};

		struct api_set_namespace_t
		{
			std::uint32_t version;      // API_SET_SCHEMA_VERSION_V6
			std::uint32_t size;
			std::uint32_t flags;        // API_SET_SCHEMA_FLAGS_*
			std::uint32_t count;
			std::uint32_t entry_offset; // to API_SET_NAMESPACE_ENTRY[count], from this struct base
			std::uint32_t hash_offset;  // to API_SET_HASH_ENTRY[count], from this struct base
			std::uint32_t hash_factor;
		};

		struct rtl_bitmap_t
		{
			std::uint32_t  size;
			std::uint32_t* buffer;
		};

		struct system_time_t
		{
			std::uint32_t low_part;
			std::int32_t  high_1_time;
			std::int32_t  high_2_time;
		};

		struct silo_user_shared_data_t
		{
			std::uint32_t	service_session_id;
			std::uint32_t	active_console_id;
			std::int64_t	console_session_foreground_process_id;
			e_nt_product_t  nt_product_type;
			std::uint32_t	suite_mask;
			std::uint32_t	shared_user_session_id; // since RS2
			bool			is_multi_session_sku;
			bool			is_state_separation_enabled;
			wchar_t			nt_system_root[ 260 ];
			std::uint16_t	user_mode_global_logger[ 16 ];
			std::uint32_t	time_zone_id; // since 21H2
			std::int32_t	time_zone_bias_stamp;
			system_time_t	time_zone_bias;
			LARGE_INTEGER	time_zone_bias_effective_start;
			LARGE_INTEGER	time_zone_bias_effective_end;
		};

		struct peb_t
		{
			// The process was cloned with an inherited address space.
			bool inherited_address_space;

			// The process has image file execution options (IFEO).
			bool read_image_file_exec_options;

			// The process has a debugger attached.
			bool being_debugged;

			union
			{
				bool bit_field;
				struct
				{
					bool image_uses_large_pages : 1;            // The process uses large image regions (4 MB).
					bool is_protected_process : 1;             // The process is a protected process.
					bool is_image_dynamically_relocated : 1;   // The process image base address was relocated.
					bool skip_patching_user32_forwarders : 1;  // The process skipped forwarders for User32.dll functions. 1 for 64-bit, 0 for 32-bit.
					bool is_packaged_process : 1;              // The process is a packaged store process (APPX/MSIX).
					bool is_app_container : 1;                 // The process has an AppContainer token.
					bool is_protected_process_light : 1;       // The process is a protected process (light).
					bool is_long_path_aware_process : 1;       // The process is long path aware.
				};
			};

			// Handle to a mutex for synchronization.
			handle    mutant;

			// Pointer to the base address of the process image.
			address_t image_base_address;

			// Pointer to the process loader data.
			peb_ldr_data_t* ldr;

			// Pointer to the process parameters
			rtl_user_process_parameters_t* process_parameters;

			// Reserved.
			address_t sub_system_data;

			// Pointer to the process default heap.
			address_t process_heap;

			// Pointer to a critical section used to synchronize access to the PEB.
			PRTL_CRITICAL_SECTION fast_peb_lock;

			// Pointer to a singly linked list used by ATL.
			address_t atl_thunk_slist_ptr;

			// Pointer to the Image File Execution Options key.
			address_t ifeo_key;

			// Cross process flags.
			union
			{
				std::uint32_t cross_process_flags;
				struct
				{
					std::uint32_t process_in_job : 1;                 // The process is part of a job.
					std::uint32_t process_initializing : 1;           // The process is initializing.
					std::uint32_t process_using_veh : 1;              // The process is using VEH.
					std::uint32_t process_using_vch : 1;              // The process is using VCH.
					std::uint32_t process_using_fth : 1;              // The process is using FTH.
					std::uint32_t process_previously_throttled : 1;   // The process was previously throttled.
					std::uint32_t process_currently_throttled : 1;    // The process is currently throttled.
					std::uint32_t process_images_hot_patched : 1;     // The process images are hot patched. // RS5
					std::uint32_t reserved_bits0 : 24;
				};
			} ;

			// User32 KERNEL_CALLBACK_TABLE (ntuser.h)
			union
			{
				address_t kernel_callback_table;
				address_t user_shared_info_ptr;
			};

			// Reserved.
			std::uint32_t system_reserved;

			// Pointer to the Active Template Library (ATL) singly linked list (32-bit)
			std::uint32_t atl_thunk_slist_ptr_32;

			// Pointer to the API Set Schema.
			api_set_namespace_t* api_set_map;

			// Counter for TLS expansion.
			std::uint32_t tls_expansion_counter;

			// Pointer to the TLS bitmap.
			rtl_bitmap_t* tls_bitmap;

			// Bits for the TLS bitmap.
			std::uint32_t tls_bitmap_bits[ 2 ];

			// Reserved for CSRSS.
			address_t read_only_shared_memory_base;

			// Pointer to the USER_SHARED_DATA for the current SILO.
			silo_user_shared_data_t* shared_data;

			// Reserved for CSRSS.
			address_t read_only_static_server_data;

			// Pointer to the ANSI code page data. (PCPTABLEINFO)
			address_t ansi_code_page_data;

			// Pointer to the OEM code page data. (PCPTABLEINFO)
			address_t oem_code_page_data;

			// Pointer to the Unicode case table data. (PNLSTABLEINFO)
			address_t unicode_case_table_data;

			// The total number of system processors.
			std::uint32_t number_of_processors;

			// Global flags for the system.
			union
			{
				std::uint32_t nt_global_flag;
				struct
				{
					std::uint32_t stop_on_exception : 1;          // FLG_STOP_ON_EXCEPTION
					std::uint32_t show_loader_snaps : 1;          // FLG_SHOW_LDR_SNAPS
					std::uint32_t debug_initial_command : 1;      // FLG_DEBUG_INITIAL_COMMAND
					std::uint32_t stop_on_hung_gui : 1;          // FLG_STOP_ON_HUNG_GUI
					std::uint32_t heap_enable_tail_check : 1;     // FLG_HEAP_ENABLE_TAIL_CHECK
					std::uint32_t heap_enable_free_check : 1;     // FLG_HEAP_ENABLE_FREE_CHECK
					std::uint32_t heap_validate_parameters : 1;  // FLG_HEAP_VALIDATE_PARAMETERS
					std::uint32_t heap_validate_all : 1;         // FLG_HEAP_VALIDATE_ALL
					std::uint32_t application_verifier : 1;      // FLG_APPLICATION_VERIFIER
					std::uint32_t monitor_silent_process_exit : 1; // FLG_MONITOR_SILENT_PROCESS_EXIT
					std::uint32_t pool_enable_tagging : 1;       // FLG_POOL_ENABLE_TAGGING
					std::uint32_t heap_enable_tagging : 1;       // FLG_HEAP_ENABLE_TAGGING
					std::uint32_t user_stack_trace_db : 1;       // FLG_USER_STACK_TRACE_DB
					std::uint32_t kernel_stack_trace_db : 1;     // FLG_KERNEL_STACK_TRACE_DB
					std::uint32_t maintain_object_type_list : 1; // FLG_MAINTAIN_OBJECT_TYPELIST
					std::uint32_t heap_enable_tag_by_dll : 1;    // FLG_HEAP_ENABLE_TAG_BY_DLL
					std::uint32_t disable_stack_extension : 1;   // FLG_DISABLE_STACK_EXTENSION
					std::uint32_t enable_csr_debug : 1;          // FLG_ENABLE_CSRDEBUG
					std::uint32_t enable_kdebug_symbol_load : 1; // FLG_ENABLE_KDEBUG_SYMBOL_LOAD
					std::uint32_t disable_page_kernel_stacks : 1;// FLG_DISABLE_PAGE_KERNEL_STACKS
					std::uint32_t enable_system_crit_breaks : 1; // FLG_ENABLE_SYSTEM_CRIT_BREAKS
					std::uint32_t heap_disable_coalescing : 1;   // FLG_HEAP_DISABLE_COALESCING
					std::uint32_t enable_close_exceptions : 1;   // FLG_ENABLE_CLOSE_EXCEPTIONS
					std::uint32_t enable_exception_logging : 1;  // FLG_ENABLE_EXCEPTION_LOGGING
					std::uint32_t enable_handle_type_tagging : 1;// FLG_ENABLE_HANDLE_TYPE_TAGGING
					std::uint32_t heap_page_allocs : 1;          // FLG_HEAP_PAGE_ALLOCS
					std::uint32_t debug_initial_command_ex : 1;  // FLG_DEBUG_INITIAL_COMMAND_EX
					std::uint32_t disable_dbg_print : 1;         // FLG_DISABLE_DBGPRINT
					std::uint32_t critsec_event_creation : 1;    // FLG_CRITSEC_EVENT_CREATION
					std::uint32_t ldr_top_down : 1;              // FLG_LDR_TOP_DOWN
					std::uint32_t enable_handle_exceptions : 1;  // FLG_ENABLE_HANDLE_EXCEPTIONS
					std::uint32_t disable_prot_dlls : 1;         // FLG_DISABLE_PROTDLLS
				} 
				nt_global_flags;
			};
		};

		struct file_header_t
		{
			std::uint16_t machine;
			std::uint16_t num_sections;
			std::uint32_t timedate_stamp;
			std::uint32_t ptr_symbols;
			std::uint32_t num_symbols;
			std::uint16_t size_optional_header;
			std::uint16_t characteristics;
		};

		union version_t
		{
			std::uint16_t identifier;
			struct
			{
				std::uint8_t major;
				std::uint8_t minor;
			};
		};

		union ex_version_t
		{
			std::uint32_t identifier;
			struct
			{
				std::uint16_t major;
				std::uint16_t minor;
			};
		};

		struct data_directory_t
		{
			std::uint32_t rva;
			std::uint32_t size;

			__forceinline bool present( ) const noexcept
			{
				return size > 0;
			}
		};

		struct raw_data_directory_t
		{
			uint32_t ptr_raw_data;
			uint32_t size;

			__forceinline bool present( ) const noexcept
			{
				return size > 0;
			}
		};

		struct data_directories_x64_t
		{
			union
			{
				struct
				{
					data_directory_t export_directory;
					data_directory_t import_directory;
					data_directory_t resource_directory;
					data_directory_t exception_directory;
					raw_data_directory_t security_directory;  // File offset instead of RVA!
					data_directory_t basereloc_directory;
					data_directory_t debug_directory;
					data_directory_t architecture_directory;
					data_directory_t globalptr_directory;
					data_directory_t tls_directory;
					data_directory_t load_config_directory;
					data_directory_t bound_import_directory;
					data_directory_t iat_directory;
					data_directory_t delay_import_directory;
					data_directory_t com_descriptor_directory;
					data_directory_t _reserved0;
				};
				data_directory_t entries[ 16 ];
			};
		};

		struct optional_header_x64_t
		{
			std::uint16_t magic;
			version_t linker_version;
			std::uint32_t size_code;
			std::uint32_t size_init_data;
			std::uint32_t size_uninit_data;
			std::uint32_t entry_point;
			std::uint32_t base_of_code;
			std::uint64_t image_base;
			std::uint32_t section_alignment;
			std::uint32_t file_alignment;
			ex_version_t os_version;
			ex_version_t img_version;
			ex_version_t subsystem_version;
			std::uint32_t win32_version_value;
			std::uint32_t size_image;
			std::uint32_t size_headers;
			std::uint32_t checksum;
			e_subsystem_id subsystem;
			std::uint16_t characteristics;
			std::uint64_t size_stack_reserve;
			std::uint64_t size_stack_commit;
			std::uint64_t size_heap_reserve;
			std::uint64_t size_heap_commit;
			std::uint32_t ldr_flags;
			std::uint32_t num_data_directories;
			data_directories_x64_t data_directories;
		};

		using optional_header_t = optional_header_x64_t;

		struct section_string_t
		{
			char short_name[ 8 ];

			__forceinline auto view( ) const noexcept
			{
				return std::string_view{ short_name };
			}

			__forceinline explicit operator std::string_view( ) const noexcept
			{
				return view( );
			}

			__forceinline auto operator[]( size_t n ) const noexcept
			{
				return view( )[ n ];
			}

			__forceinline bool operator==( const section_string_t& other ) const
			{
				return view( ).compare( other.view( ) ) == 0;
			}
		};

		struct export_directory_t
		{
			uint32_t characteristics;
			uint32_t timedate_stamp;
			version_t version;
			uint32_t name;
			uint32_t base;
			uint32_t num_functions;
			uint32_t num_names;
			uint32_t rva_functions;
			uint32_t rva_names;
			uint32_t rva_name_ordinals;

			__forceinline auto rva_table( address_t base_address, nt_headers_t* nt_headers = nullptr, bool mapped = false ) const
			{
				return base_address.ptr< std::uint32_t >( rva_2_offset( rva_functions, nt_headers, mapped ) );
			}

			__forceinline auto ordinal_table( address_t base_address, nt_headers_t* nt_headers = nullptr, bool mapped = false ) const
			{
				return base_address.ptr< std::uint16_t >( rva_2_offset( rva_name_ordinals, nt_headers, mapped ) );
			}
		};

		struct section_header_t
		{
			section_string_t name;
			union
			{
				std::uint32_t physical_address;
				std::uint32_t virtual_size;
			};
			std::uint32_t virtual_address;

			std::uint32_t size_raw_data;
			std::uint32_t ptr_raw_data;

			std::uint32_t ptr_relocs;
			std::uint32_t ptr_line_numbers;
			std::uint16_t num_relocs;
			std::uint16_t num_line_numbers;

			std::uint32_t characteristics_flags;
		};

		struct nt_headers_t
		{
			std::uint32_t		signature;
			file_header_t		file_header;
			optional_header_t	optional_header;

			__forceinline section_header_t* get_sections( )
			{
				return ( section_header_t* )( ( std::uint8_t* )&optional_header + file_header.size_optional_header );
			}

			__forceinline section_header_t* get_section( std::size_t n )
			{
				return n >= file_header.num_sections ? nullptr : get_sections( ) + n;
			}

			__forceinline const section_header_t* get_sections( ) const
			{
				return const_cast< nt_headers_t* >( this )->get_sections( );
			}

			__forceinline const section_header_t* get_section( std::size_t n ) const
			{
				return const_cast< nt_headers_t* >( this )->get_section( n );
			}

			__forceinline section_header_t* rva_to_section( std::uint32_t rva )
			{
				for ( size_t i = 0; i != file_header.num_sections; i++ )
				{
					auto section = get_section( i );
					if ( section->virtual_address <= rva &&
						rva < ( section->virtual_address + section->virtual_size ) )
						return section;
				}
				return nullptr;
			}

			__forceinline const section_header_t* rva_to_section( std::uint32_t rva ) const
			{
				return const_cast< nt_headers_t* >( this )->rva_to_section( rva );
			}
		};

		struct dos_header_t
		{
			std::uint16_t e_magic;
			std::uint16_t e_cblp;
			std::uint16_t e_cp;
			std::uint16_t e_crlc;
			std::uint16_t e_cparhdr;
			std::uint16_t e_minalloc;
			std::uint16_t e_maxalloc;
			std::uint16_t e_ss;
			std::uint16_t e_sp;
			std::uint16_t e_csum;
			std::uint16_t e_ip;
			std::uint16_t e_cs;
			std::uint16_t e_lfarlc;
			std::uint16_t e_ovno;
			std::uint16_t e_res[ 4 ];
			std::uint16_t e_oemid;
			std::uint16_t e_oeminfo;
			std::uint16_t e_res2[ 10 ];
			std::uint32_t e_lfanew;

			__forceinline nt_headers_t* get_nt_headers( )
			{
				return ( nt_headers_t* )( ( uint8_t* )this + e_lfanew );
			}

			__forceinline const nt_headers_t* get_nt_headers( ) const
			{
				return const_cast< dos_header_t* >( this )->get_nt_headers( );
			}

			__forceinline file_header_t* get_file_header( )
			{
				return &get_nt_headers( )->file_header;
			}

			__forceinline const file_header_t* get_file_header( ) const
			{
				return &get_nt_headers( )->file_header;
			}
		};

		struct image_t
		{
			dos_header_t dos_header;

			inline dos_header_t* get_dos_headers( )
			{
				return &dos_header;
			}

			__forceinline const dos_header_t* get_dos_headers( ) const
			{
				return &dos_header;
			}

			__forceinline file_header_t* get_file_header( )
			{
				return dos_header.get_file_header( );
			}

			__forceinline const file_header_t* get_file_header( ) const
			{
				return dos_header.get_file_header( );
			}

			__forceinline nt_headers_t* get_nt_headers( )
			{
				return dos_header.get_nt_headers( );
			}

			__forceinline const nt_headers_t* get_nt_headers( ) const
			{
				return dos_header.get_nt_headers( );
			}

			__forceinline optional_header_t* get_optional_header( )
			{
				return &get_nt_headers( )->optional_header;
			}

			__forceinline const optional_header_t* get_optional_header( ) const
			{
				return &get_nt_headers( )->optional_header;
			}

			__forceinline data_directory_t* get_directory( e_directory_id id )
			{
				auto nt_hdrs = get_nt_headers( );
				if ( nt_hdrs->optional_header.num_data_directories <= id )
					return nullptr;
				data_directory_t* dir = &nt_hdrs->optional_header.data_directories.entries[ id ];
				return dir->present( ) ? dir : nullptr;
			}

			__forceinline const data_directory_t* get_directory( e_directory_id id ) const
			{
				return const_cast< image_t* >( this )->get_directory( id );
			}
		};

		struct export_t
		{
			std::string_view name;
			address_t        address;
			std::uint32_t    ordinal;
		};

		class exports_t
		{
		public:

			__forceinline explicit exports_t( address_t base ) noexcept
				: m_module_base( base ), m_export_dir( get_export_directory( base ) )
			{ }

			__forceinline explicit exports_t( address_t base, bool mapped ) noexcept
				: m_module_base( base ), m_export_dir( get_export_directory( base, mapped ) ), m_mapped{ mapped }
			{ }	

			__forceinline std::size_t size( ) const noexcept
			{
				return m_export_dir->num_names;
			}

			__forceinline const export_directory_t* directory( ) const noexcept
			{
				return m_export_dir;
			}

			__forceinline auto name( std::size_t index ) const noexcept
			{
				if ( ! m_export_dir->rva_names )
					return std::string_view{ };

				const auto rva_names_ptr = m_module_base.offset( rva_2_offset( m_export_dir->rva_names, m_module_base.ptr< image_t >( )->get_nt_headers( ), m_mapped ) ).as< const uint32_t* >( );
				auto str = m_module_base.ptr< const char >( rva_2_offset( rva_names_ptr[ index ], m_module_base.ptr< image_t >( )->get_nt_headers( ), m_mapped ) );
				return std::string_view{ str };
			}

			__forceinline auto ordinal( std::size_t index ) const noexcept
			{
				const auto rva_table_ptr     = reinterpret_cast< std::uint32_t* >( m_module_base.raw( ) + pe::rva_2_offset( m_export_dir->rva_functions, m_module_base.ptr< image_t >( )->get_nt_headers( ), m_mapped ) );
				const auto ordinal_table_ptr = reinterpret_cast< std::uint16_t* >( m_module_base.raw( ) + pe::rva_2_offset( m_export_dir->rva_name_ordinals, m_module_base.ptr< image_t >( )->get_nt_headers( ), m_mapped ) );

				const auto ordinal = ordinal_table_ptr[ index ];
				const auto rva_function = rva_table_ptr[ ordinal ];

				return pe::rva_2_offset( rva_function, m_module_base.ptr< image_t >( )->get_nt_headers( ), m_mapped );
			}

			__forceinline auto address( std::size_t index ) const noexcept
			{
				const auto rva_table_ptr = reinterpret_cast< std::uint32_t* >( m_module_base.raw( ) + pe::rva_2_offset( m_export_dir->rva_functions, m_module_base.ptr< image_t >( )->get_nt_headers( ), m_mapped ) );
				const auto ordinal_table_ptr = reinterpret_cast< std::uint16_t* >( m_module_base.raw( ) + pe::rva_2_offset( m_export_dir->rva_name_ordinals, m_module_base.ptr< image_t >( )->get_nt_headers( ), m_mapped ) );

				const auto ordinal      = ordinal_table_ptr[ index ];
				const auto rva_function = rva_table_ptr[ ordinal ];

				return m_module_base.offset( pe::rva_2_offset( rva_function, m_module_base.ptr< image_t >( )->get_nt_headers( ), m_mapped ) );
			}

			class iterator
			{
			public:

				using iterator_category = std::bidirectional_iterator_tag;
				using value_type = export_t;
				using difference_type = std::ptrdiff_t;
				using pointer = value_type*;
				using reference = value_type&;

				iterator( ) : m_exports( nullptr ), m_index( 0 ), m_value( {} ) { };
				~iterator( ) = default;
				iterator( const iterator& ) = default;
				iterator( iterator&& ) = default;
				iterator& operator=( iterator&& ) = default;

				iterator( const exports_t* exports, std::size_t index ) noexcept
					: m_exports( exports ), m_index( index ), m_value( )
				{
					update_value( );
				}

				reference operator*( ) const noexcept
				{
					return m_value;
				}

				pointer operator->( ) const noexcept
				{
					return &m_value;
				}

				iterator& operator=( const iterator& other ) noexcept
				{
					if ( this != &other )
					{
						m_index = other.m_index;
						m_value = other.m_value;
					}
					return *this;
				}

				iterator& operator++( ) noexcept
				{
					if ( m_index < m_exports->size( ) )
					{
						++m_index;

						if ( m_index < m_exports->size( ) )
							update_value( );
						else
							reset_value( );
					}
					else
					{
						reset_value( );
					}
					return *this;
				}

				iterator operator++( int ) noexcept
				{
					iterator temp = *this;
					++( *this );
					return temp;
				}

				iterator& operator--( ) noexcept
				{
					if ( m_index > 0 )
					{
						--m_index;
						update_value( );
					}
					return *this;
				}

				iterator operator--( int ) noexcept
				{
					iterator temp = *this;
					--( *this );
					return temp;
				}

				bool operator==( const iterator& other ) const noexcept
				{
					return m_index == other.m_index && m_exports == other.m_exports;
				}

				bool operator!=( const iterator& other ) const noexcept
				{
					return !( *this == other );
				}

			private:

				void update_value( ) noexcept
				{
					if ( m_index < m_exports->size( ) )
					{
						const auto address = m_exports->address( m_index );
						m_value = value_type
						{
							.name = m_exports->name( m_index ),
							.address = address,
							.ordinal = m_exports->ordinal( m_index ),
						};
					}
				}

				void reset_value( ) noexcept
				{
					m_value = value_type{};
				}

				const exports_t* m_exports;
				std::size_t m_index;
				mutable value_type m_value;
			};

			static_assert( std::bidirectional_iterator<iterator> );

			iterator begin( ) const noexcept
			{
				return iterator( this, 0 );
			}
			iterator end( ) const noexcept
			{
				return iterator( this, size( ) );
			}

			iterator find( std::uint64_t export_name ) const noexcept
			{
				if ( export_name == 0 )
					return end( );

				auto it = std::ranges::find_if
				( 
					*this, 
					[ export_name ]( const export_t& data ) -> bool
					{
						return export_name == fnv::hash_runtime( data.name.data( ) );
					} 
				);

				return it;
			}

			iterator find_if( std::predicate<iterator::value_type> auto predicate ) const
			{
				return std::ranges::find_if( *this, predicate );
			}

		private:

			export_directory_t* get_export_directory( address_t base_address, bool mapped = false ) const noexcept
			{
				const auto image = base_address.ptr< image_t >( );
				const auto export_data_dir =
					image->get_optional_header( )->data_directories.export_directory;
				return m_module_base.offset< export_directory_t* >( rva_2_offset( export_data_dir.rva, image->get_nt_headers( ), mapped ) );
			}

			address_t           m_module_base;
			export_directory_t* m_export_dir{ nullptr };
			bool m_mapped { false };

		};

		class module_t
		{
		public:

			constexpr module_t( ) noexcept = default;

			module_t( ldr_table_entry_t* module_data ) 
				: m_data( module_data ) 
			{ }

			module_t( std::uint64_t module_name )
				: m_data( find( module_name ).ldr_table_entry( ) ) 
			{ }

			module_t( const module_t& instance ) = default;
			module_t( module_t&& instance ) = default;
			module_t& operator=( const module_t& instance ) = default;
			module_t& operator=( module_t&& instance ) = default;
			~module_t( ) = default;

			__forceinline ldr_table_entry_t* ldr_table_entry( ) const noexcept
			{
				return m_data;
			}

			__forceinline auto base_address( ) const noexcept
			{
				return m_data->base_address;
			}

			__forceinline auto native_handle( ) const noexcept
			{
				return base_address( ).ptr( );
			}

			__forceinline auto entry_point( ) const noexcept
			{
				return m_data->entry_point;
			}

			__forceinline auto name_hashed( ) const noexcept
			{ 
				auto hash_base = fnv64::hash_init( );
				char buf[ 4 ];
				for ( const auto* p = m_data->name.buffer; *p != L'\0'; ++p )
				{
					const auto len = ::WideCharToMultiByte( CP_UTF8, 0, p, 1, buf, sizeof( buf ), nullptr, nullptr );

					if ( len <= 0 )
						continue;

					for ( auto i = 0; i < len; ++i )
						hash_base = fnv64::hash_byte( hash_base, static_cast< std::uint8_t >( buf[ i ] ) );
				}
				return hash_base;
			}

			__forceinline auto name( ) const noexcept
			{
				return m_data == nullptr ? std::string{ } : m_data->name.to_string( );
			}

			__forceinline auto sanitized_name( ) const noexcept
			{
				return m_data == nullptr ? std::string{ } : m_data->name.to_sanitized_string( );
			}

			__forceinline auto filepath( ) const noexcept
			{
				return m_data == nullptr ? std::string{ } : m_data->name.to_string( );
			}

			__forceinline auto present( ) const noexcept
			{
				return m_data != nullptr;
			}

			__forceinline auto exports( ) const noexcept
			{
				return exports_t{ m_data->base_address };
			}

			__forceinline bool operator==( const module_t& other ) const noexcept
			{
				return m_data == other.m_data;
			}

			__forceinline bool operator==( std::uint64_t module_name_hash ) const noexcept
			{
				const auto name = this->sanitized_name( );
				if ( name.size( ) <= 0 )
					return false;
				return fnv::hash_runtime( name.c_str( ), name.size( ) ) == module_name_hash;
			}

			__forceinline bool operator!=( std::uint64_t module_name_hash ) const noexcept
			{
				return !operator==( module_name_hash );
			}

			__forceinline explicit operator bool( ) const noexcept
			{
				return present( );
			}

		private:

			__forceinline module_t find( std::uint64_t module_hash ) const;

			ldr_table_entry_t* m_data { nullptr };

		};

		class modules_t
		{
		public:

			__forceinline explicit modules_t( )
			{
				auto base_entry = &pe::current_peb( )->ldr->in_load_order_links;
				this->m_begin   = base_entry->flink;
				this->m_end     = base_entry;
			}

			__forceinline modules_t& load_next( )
			{
				m_begin = m_begin->flink;
				return *this;
			}

			class iterator
			{
			public:

				using iterator_category = std::bidirectional_iterator_tag;
				using value_type        = module_t;
				using difference_type   = std::ptrdiff_t;
				using pointer           = value_type*;
				using reference         = value_type&;

				__forceinline iterator( ) noexcept
					: m_entry( nullptr ), m_value{ }
				{ }

				~iterator( ) = default;
				iterator( const iterator& ) = default;
				iterator( iterator&& ) = default;
				iterator& operator=( iterator&& ) = default;

				__forceinline iterator( list_entry_t* entry ) noexcept
					: m_entry( entry )
				{ 
					on_update( );
				}

				pointer operator->( ) const noexcept
				{
					return &m_value;
				}

				iterator& operator=( const iterator& other ) noexcept
				{
					if ( this != &other )
					{
						m_entry = other.m_entry;
						on_update( );
					}
					return *this;
				}

				iterator& operator++( ) noexcept
				{
					m_entry = m_entry->flink;
					on_update( );
					return *this;
				}

				iterator operator++( int ) noexcept
				{
					iterator temp = *this;
					++( *this );
					return temp;
				}

				iterator& operator--( ) noexcept
				{
					m_entry = m_entry->blink;
					on_update( );
					return *this;
				}

				iterator operator--( int ) noexcept
				{
					iterator temp = *this;
					--( *this );
					return temp;
				}

				bool operator==( const iterator& other ) const noexcept
				{
					return m_entry == other.m_entry;
				}

				bool operator!=( const iterator& other ) const noexcept
				{
					return !( *this == other );
				}

				reference operator*( ) const noexcept
				{
					return m_value;
				}

			private:

				void on_update( ) const noexcept
				{
					auto table_entry = pe::containing_record( m_entry, &ldr_table_entry_t::in_load_order_links );
					m_value = value_type{ table_entry };
				}

				list_entry_t*      m_entry;
				mutable value_type m_value;

			};

			static_assert( std::bidirectional_iterator<iterator> );

			iterator begin( ) const noexcept
			{
				return iterator( m_begin );
			}
			iterator end( ) const noexcept
			{
				return iterator( m_end );
			}

			[[nodiscard]] __forceinline iterator
				find_if( std::predicate< iterator::value_type > auto predicate ) const noexcept
			{
				return std::ranges::find_if( *this, predicate );
			}

			__forceinline void 
				for_each( const std::function< void( module_t& ) >& f ) noexcept
			{
				for ( auto& m : *this )
				{
					f( m );
				}
			}

			__forceinline void 
				for_each( const std::function< void( const module_t& ) >& f ) const noexcept
			{
				for ( const auto& m : *this )
				{
					f( m );
				}
			}

		private:

			list_entry_t* m_begin	{ };
			list_entry_t* m_end		{ };
 
		};

		class exported_symbol_t
		{
		public:

			__forceinline constexpr exported_symbol_t( ) = default;

			explicit exported_symbol_t( std::uint64_t export_name, std::uint64_t module_hash = 0, bool no_crt = false ) noexcept
				: m_data( resolve_export_address( export_name, module_hash, no_crt ) )
			{ }

			exported_symbol_t( const exported_symbol_t& instance ) = default;
			exported_symbol_t( exported_symbol_t&& instance ) = default;
			exported_symbol_t& operator=( const exported_symbol_t& instance ) = default;
			exported_symbol_t& operator=( exported_symbol_t&& instance ) = default;
			~exported_symbol_t( ) = default;

			__forceinline auto address( ) const noexcept
			{
				return m_data.m_address;
			}

			__forceinline auto location( ) const noexcept
			{
				return m_data.m_base_dll;
			}

			__forceinline auto present( ) const noexcept
			{
				return static_cast< bool >( m_data.m_address );
			}

			__forceinline bool operator==( address_t other ) const noexcept
			{
				return m_data.m_address == other;
			}

			__forceinline explicit operator bool( ) const noexcept
			{
				return present( );
			}

			__forceinline explicit operator address_t( ) const noexcept
			{
				return address( );
			}

		private:

			struct full_export_data_t
			{
				address_t    m_address{ };
				pe::module_t m_base_dll{ };
			};

			__forceinline full_export_data_t resolve_export_address( std::uint64_t export_name, std::uint64_t module_hash, bool no_crt ) const noexcept
			{
				if ( export_name == 0 )
					return {};

				const auto process_modules = modules_t{ }.load_next( );
				const bool is_module_specified = module_hash != 0;

				for ( const auto& module : process_modules )
				{
					if ( is_module_specified && ( no_crt ? module.name_hashed( ) != module_hash : module != module_hash ) )
						continue;

					exports_t exports{ module.base_address( ) };

					for ( const auto& e : exports )
					{
						if ( fnv::hash_runtime( e.name.data( ) ) == export_name )
							return { e.address, module };
					} 
				}

				return { };
			}

			full_export_data_t m_data{ };

		};

		constexpr bool pe::nt_success( const nt_status s )
		{
			return s >= 0;
		}

		constexpr handle pe::current_process( )
		{
			return reinterpret_cast< handle >( -1 );
		}

		constexpr handle pe::current_thread( )
		{
			return reinterpret_cast< handle >( -2 );
		}

		peb_t* pe::current_peb( )
		{
	#if COMPILER_CLANG
			peb_t* r;
			__asm__ __volatile__( "movq %%gs:0x60, %0" : "=r"( r ) ); 
			return r;
	#else
			return reinterpret_cast< peb_t* >( __readgsqword( 0x60 ) );
	#endif
		}

		std::string pe::utf8_encode( const std::wstring& wstr )
		{
			const auto size_needed = WideCharToMultiByte( CP_UTF8, 0, &wstr[ 0 ], std::int32_t( wstr.size( ) ), nullptr, 0, nullptr, nullptr );
			std::string out_str( size_needed, 0 );
			WideCharToMultiByte( CP_UTF8, 0, &wstr[ 0 ], std::int32_t( wstr.size( ) ), &out_str[ 0 ], size_needed, nullptr, nullptr );
			return out_str;
		}

		auto exported_symbol( std::uint64_t export_name, std::uint64_t module_name, bool crt_less )
		{
			return ::thorazine::pe::exported_symbol_t( export_name, module_name, crt_less );
		}

		module_t pe::module_t::find( std::uint64_t module_hash ) const
		{
			modules_t modules { };
			auto it = modules.find_if
			( 
				[ =, this ]( const module_t& dll ) -> bool
				{
					return dll == module_hash;
				}
			);
			return it != modules.end( ) ? *it : module_t{ };
		}

		template< typename T >
		T rva_2_offset( std::uint32_t rva, nt_headers_t* nt_headers, bool mapped_in_memory )
		{
			if ( !rva || !nt_headers || !mapped_in_memory )
				return rva;

			auto sec = nt_headers->get_sections( );

			if ( !sec )
				return rva;

			for ( std::size_t i = 0; i < nt_headers->file_header.num_sections; i++ )
			{
				if ( rva >= sec->virtual_address && rva < sec->virtual_address + sec->virtual_size )
					break;
				sec++;
			}

			return static_cast< T >( rva - sec->virtual_address + sec->ptr_raw_data );
		}
	}
}
#endif