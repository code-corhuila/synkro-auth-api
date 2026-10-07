/**
 * TEMPORARY in-memory adapters standing in for persistence that does not exist yet.
 *
 * synkro-auth-db currently has only auth_schema and its writer role: no system_user or
 * refresh_token table. A follow-up story adds them and replaces everything in this
 * package with Postgres adapters behind the same ports, the same split
 * synkro-products-api made between HU-PRO-03 and HU-PRO-08. Do not extend this
 * package with features: it is meant to be deleted.
 */
package co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory;
