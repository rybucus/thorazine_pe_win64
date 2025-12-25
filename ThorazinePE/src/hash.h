#pragma once

#include <cstdint>
#include <cstddef>
#include <type_traits>
#include <iostream>

namespace thorazine::detail
{

template < typename T, T k_offset_basis, T k_prime >
struct size_dependant_data_t
{
    using type_t = T;

    constexpr static auto offset_basis = k_offset_basis;
    constexpr static auto prime = k_prime;
};

template < std::size_t bits >
struct size_selector_t : std::false_type { };

template < >
struct size_selector_t< 32 > : size_dependant_data_t< std::uint32_t, 0x811c9dc5ul, 16777619ul > { };

template < >
struct size_selector_t< 64 > : size_dependant_data_t< std::uint64_t, 0xcbf29ce484222325ull, 1099511628211ull > { };

template< std::size_t size >
class basic_hasher_t
{
public:
    using self_t = basic_hasher_t< size >;
    using data_t = detail::size_selector_t< size >;
    using hash_t = typename data_t::type_t;

public:
    constexpr basic_hasher_t( ) = default;

    constexpr basic_hasher_t( std::integral auto value )
        : basic_hasher_t{ static_cast< hash_t >( value ) }
    {

    }

    constexpr basic_hasher_t( hash_t hash ) : m_hash{ hash }
    {

    }

    consteval basic_hasher_t( const char* str, const std::size_t size ) : m_hash{ hash_constexpr( str, size ) }
    {

    }

    template< std::size_t N >
    consteval basic_hasher_t( const char( &str )[ N ], const std::size_t size = N - 1 ) : m_hash{ hash_constexpr( str, size ) }
    {

    }

    template< typename T >
    consteval basic_hasher_t( const T& obj ) : m_hash{ hash_constexpr( obj ) }
    {

    }

    self_t operator( )( const char* str ) const
    {
        return hash_runtime( str );
    }

    self_t operator( )( const char* str, const std::size_t size ) const
    {
        return hash_runtime( str, size );
    }

    template< typename T >
    self_t operator( )( const T& obj ) const
    {
        return hash_runtime< T >( obj );
    }

    constexpr hash_t get( ) const
    {
        return m_hash;
    }

    constexpr explicit operator hash_t( ) const
    {
        return m_hash;
    }

    friend std::ostream& operator<<( std::ostream& os, const self_t& h )
    {
        return os << h.get( );
    }

public:
    static constexpr hash_t hash_byte( hash_t current, std::uint8_t byte )
    {
        return ( current ^ byte ) * data_t::prime;
    }

    template< std::size_t N >
    static constexpr hash_t hash_constexpr( const char( &str )[ N ], const std::size_t size = N - 1 )
    {
        const auto prev_hash = size == 1 ? data_t::offset_basis : hash_constexpr( str, size - 1 );
        return hash_byte( prev_hash, str[ size - 1 ] );
    }

    static constexpr hash_t hash_constexpr( const char* str, const std::size_t size )
    {
        auto hash = data_t::offset_basis;
        for ( std::size_t i = 0; i < size; ++i )
        {
            hash = hash_byte( hash, str[ i ] );
        }
        return hash;
    }

    template< typename T >
    static constexpr hash_t hash_constexpr( const T& obj )
    {
        auto hash = data_t::offset_basis;
        for ( std::size_t i = 0; i < obj.size( ); ++i )
        {
            hash = hash_byte( hash, obj[ i ] );
        }
        return hash;
    }

    static hash_t hash_runtime( const char* str )
    {
        auto hash = data_t::offset_basis;
        while ( *str )
        {
            hash = hash_byte( hash, *str++ );
        }
        return hash;
    }

    static hash_t hash_runtime( const char* str, const std::size_t size )
    {
        auto hash = data_t::offset_basis;
        for ( std::size_t i = 0; i < size; ++i )
        {
            hash = hash_byte( hash, str[ i ] );
        }
        return hash;
    }

    template< typename T >
    static hash_t hash_runtime( const T& obj )
    {
        auto hash = data_t::offset_basis;
        for ( std::size_t i = 0; i < obj.size( ); ++i )
        {
            hash = hash_byte( hash, obj[ i ] );
        }
        return hash;
    }

private:
    hash_t m_hash{ };
};

using hasher_t = basic_hasher_t< sizeof( void* ) * 8 >;
using hash_t   = hasher_t::hash_t;

template <std::size_t N>
inline consteval hash_t hash( const char( &str )[ N ] ) noexcept
{
    return hasher_t{ str }.get( );
}

template< typename T >
inline consteval hash_t hash( const T& obj ) noexcept
{
    return hasher_t{ obj }.get( );
}

template< typename T >
inline hash_t hash_runtime( const T& obj ) noexcept
{
    return hasher_t{ }( obj ).get( );
}

inline hash_t hash_runtime( const char* str ) noexcept
{
    return hasher_t{ }( str ).get( );
}

inline hash_t hash_runtime( const char* str, const std::size_t size ) noexcept
{
    return hasher_t{ }( str ).get( );
}

} // namespace thorazine::detail