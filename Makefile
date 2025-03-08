NAME = ft_malcolm

# Compilateur et options de compilation
CC = gcc
CCFLAGS = -Wall -Wextra -Werror -g3 -I srcs/include

# Répertoire pour les fichiers objets
OBJDIR = obj

# Liste des fichiers sources avec chemins relatifs corrects
SRCS = srcs/utils.c\
	srcs/lib/ft_memset.c\
	srcs/lib/ft_strcmp.c\
	srcs/lib/ft_strtok.c\
	srcs/parse.c\
	srcs/main.c

OBJS = $(SRCS:srcs/%.c=$(OBJDIR)/%.o)

# Fichiers de dépendances
DEPS = $(OBJS:.o=.d)
 
# Cible par défaut
all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CCFLAGS) -o $@ $^


$(OBJDIR)/%.o: srcs/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CCFLAGS) -MMD -c $< -o $@

# Inclure les fichiers de dépendance générés
-include $(DEPS)

# Nettoyage des fichiers objets et des dépendances
clean:
	rm -rf $(OBJDIR)

# Nettoyage complet (objets + exécutable)
fclean: clean
	rm -f $(NAME)

# Recompilation complète
re: fclean all

# Phony targets pour éviter les conflits avec des fichiers réels
.PHONY: all clean fclean re