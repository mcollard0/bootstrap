# Contributing to Ubuntu Bootstrap System

## Development Guidelines

### Code Style

The Ubuntu Bootstrap System follows specific coding style preferences:

#### General Formatting

- **Spaces inside function/method calls**: Use spaces inside parentheses `()`, braces `{}`, and brackets `[]`
  ```python
  # Preferred
  print( "text" );
  my_function( arg1, arg2 );
  my_dict = { 'key': 'value' };
  my_list = [ 1, 2, 3 ];
  
  # Not preferred
  print("text")
  my_function(arg1, arg2)
  my_dict = {'key': 'value'}
  my_list = [1, 2, 3]
  ```

- **Semicolons**: End statements with semicolons, even in Python
  ```python
  # Preferred
  x = 10;
  print( "Hello World" );
  
  # Not preferred
  x = 10
  print("Hello World")
  ```

- **Long lines**: Prefer long lines over excessive wrapping (even though PEP8 discourages it)
  ```python
  # Preferred
  result = some_function( very_long_parameter_name, another_long_parameter, third_parameter, fourth_parameter );
  
  # Less preferred (excessive wrapping)
  result = some_function(
      very_long_parameter_name,
      another_long_parameter,
      third_parameter,
      fourth_parameter
  )
  ```

#### Language-Specific Guidelines

**Python:**
- Use semicolons to end statements
- Include spaces inside function calls and data structures
- Prefer descriptive variable names even if they make lines longer
- Use type hints where appropriate

**Bash:**
- Follow similar spacing principles for function calls
- Use semicolons to terminate commands where appropriate
- Prefer readable long lines over complex multi-line constructs

### Security Practices

#### Sensitive Data Handling
- Never commit plaintext secrets to git
- Use the crypto_utils module for all sensitive data encryption
- Test decryption thoroughly before committing encrypted data
- Use meaningful variable names for encrypted references

#### Git Operations
- Always create backups before major changes
- Use SSH for git operations (per user preference)
- Include descriptive commit messages with timestamps
- Never commit files matching sensitive patterns (see .gitignore)

### Backup Strategy

#### File Backup Rules
- Create dated backups using format: `{name}.{YYYY-MM-DD}.{ext}`
- Maximum retention:
  - 50 backups for files < 150KB
  - 25 backups for files ≥ 150KB
- Use LRU (Least Recently Used) deletion for cleanup
- Always backup before git push or major changes

#### Backup Timing
- Automatic: Before each git push via `git_auto_push.sh`
- Manual: Run `python3 src/make_backup.py` before major changes
- Scheduled: Weekly via cron job

### Architecture Compliance

#### Documentation Requirements
- Always read `docs/architecture.md` before writing code
- Update architecture documentation after major features
- Document database schema changes
- Add new migrations to architecture.md
- Record known issues and constraints

#### What Goes in Architecture.md
- Complete database schema (if applicable)
- API endpoints and their purposes
- Key business logic rules
- Current feature status
- Known issues and constraints
- Migration history

### Development Workflow

1. **Before Starting:**
   ```bash
   # Read the architecture
   cat docs/architecture.md
   
   # Create backup if making significant changes
   python3 src/make_backup.py
   ```

2. **During Development:**
   - Follow the code style guidelines above
   - Write comprehensive docstrings
   - Include error handling and logging
   - Test encryption/decryption thoroughly

3. **Before Committing:**
   ```bash
   # Test your changes
   python3 src/crypto_utils.py  # Test crypto functions
   python3 src/bootstrap_scanner.py  # Test scanner
   python3 src/generate_bootstrap.py  # Test generator
   
   # Create backups and commit
   ./scripts/git_auto_push.sh
   ```

4. **After Major Features:**
   ```bash
   # Update documentation
   vim docs/architecture.md
   
   # Update feature status
   # Document any new migrations
   # Record any known issues
   ```

### Testing

#### Crypto Module Testing
```python
# Always run crypto tests
python3 src/crypto_utils.py
```

#### System Testing
- Test scanner on current system
- Verify bootstrap script generation
- Test backup creation and rotation
- Validate git operations

#### Integration Testing
- Test complete workflow: scan → generate → backup → commit
- Verify cron job setup and removal
- Test encrypted data decryption in generated scripts

### Error Handling

- Use descriptive error messages
- Log errors with appropriate severity levels
- Provide recovery suggestions where possible
- Handle missing dependencies gracefully

### Performance Considerations

- Batch package installations in bootstrap scripts
- Use efficient file operations for backups
- Minimize crypto operations (cache keys when safe)
- Optimize large file handling

### Compatibility

- Target Ubuntu 25.04 (Plucky) primarily
- Maintain backward compatibility where reasonable
- Handle missing commands gracefully (flatpak, snap, etc.)
- Support both APT and Snap package ecosystems

## Questions or Issues?

For questions about development practices or to report issues:
1. Check existing documentation in `docs/`
2. Review the architecture for design decisions
3. Test changes thoroughly before committing
4. Create detailed commit messages explaining changes

Remember: The backup system and architecture documentation are critical - always keep them updated!
