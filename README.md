# SAMM Circuits

## Dependencies

Noir v0.34.0 <> BB v0.55.0

## Compilation

```
  nargo check
```

## Run tests

```
  nargo test
```

## Generate/verify proof
1. Generate witness of your Noir program running:
    ```
      nargo execute witness-samm
    ```

2. Prove the valid execution of your Noir program running:
    ```
      bb prove_ultra_honk -b ./target/SAMM.json -w ./target/witness-samm.gz -o ./target/proof
    ```

3. Compute the verification key for your Noir program running:
    ```
      bb write_vk_ultra_honk -b ./target/SAMM.json -o ./target/vk
    ```

4. Verify your proof running:
    ```
      bb verify_ultra_honk -k ./target/vk -p ./target/proof
    ```
    If successful, the verification will complete in silence; if unsuccessful, the command will trigger logging of the corresponding error.